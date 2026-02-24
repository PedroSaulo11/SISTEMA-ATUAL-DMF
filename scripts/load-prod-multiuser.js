/* eslint-disable no-console */
const { performance } = require('perf_hooks');

function env(name, fallback = null) {
  const raw = process.env[name];
  if (raw == null || raw === '') return fallback;
  return String(raw).trim();
}

function required(name) {
  const value = env(name);
  if (!value) throw new Error(`Missing required env: ${name}`);
  return value;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function percentile(values, p) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

async function request(url, { method = 'GET', token = '', body = null } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const start = performance.now();
  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const elapsed = performance.now() - start;
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch (_) { json = null; }
  return { status: res.status, elapsed, json, text };
}

async function main() {
  const base = required('BASE_URL').replace(/\/+$/, '');
  const token = required('ACCESS_TOKEN');
  const company = env('TEST_COMPANY', 'Real Energy');
  const workers = Math.max(1, Number(env('LOAD_WORKERS', '8')) || 8);
  const rounds = Math.max(1, Number(env('LOAD_ROUNDS', '20')) || 20);
  const pauseMs = Math.max(0, Number(env('LOAD_PAUSE_MS', '100')) || 100);

  const latencies = [];
  let ok = 0;
  let fail = 0;
  let conflicts = 0;
  let deleted = 0;

  console.log(`[load] base=${base} company=${company} workers=${workers} rounds=${rounds}`);

  async function oneRound(roundId, workerId) {
    const id = `load-${Date.now()}-${workerId}-${roundId}-${Math.random().toString(36).slice(2, 8)}`;
    const create = await request(`${base}/api/flow-payments?company=${encodeURIComponent(company)}`, {
      method: 'POST',
      token,
      body: {
        id,
        fornecedor: 'Load Supplier',
        data: '24/02/2026',
        descricao: 'Load test payment',
        valor: 12.34,
        centro: 'Teste',
        categoria: 'Operacional',
        company
      }
    });
    latencies.push(create.elapsed);
    if (create.status !== 200) {
      fail += 1;
      return;
    }

    const signUrl = `${base}/api/flow-payments/${encodeURIComponent(id)}/sign?company=${encodeURIComponent(company)}`;
    const bodyA = { assinatura: { hash: `a-${id}`, dataISO: new Date().toISOString() }, company };
    const bodyB = { assinatura: { hash: `b-${id}`, dataISO: new Date().toISOString() }, company };
    const [a, b] = await Promise.all([
      request(signUrl, { method: 'PATCH', token, body: bodyA }),
      request(signUrl, { method: 'PATCH', token, body: bodyB })
    ]);
    latencies.push(a.elapsed, b.elapsed);
    const statuses = [a.status, b.status].sort((x, y) => x - y);
    if (statuses[0] === 200 && statuses[1] === 409) {
      ok += 1;
      conflicts += 1;
    } else {
      fail += 1;
    }

    const del = await request(`${base}/api/flow-payments/${encodeURIComponent(id)}?company=${encodeURIComponent(company)}`, {
      method: 'DELETE',
      token
    });
    latencies.push(del.elapsed);
    if (del.status === 200) deleted += 1;
  }

  for (let round = 0; round < rounds; round += 1) {
    const jobs = [];
    for (let worker = 0; worker < workers; worker += 1) {
      jobs.push(oneRound(round, worker));
    }
    await Promise.all(jobs);
    if (pauseMs > 0) await sleep(pauseMs);
  }

  const total = ok + fail;
  const p50 = percentile(latencies, 50);
  const p95 = percentile(latencies, 95);
  const max = latencies.length ? Math.max(...latencies) : 0;

  console.log(`[load] done total=${total} ok=${ok} fail=${fail} conflicts=${conflicts} deleted=${deleted}`);
  console.log(`[load] latency_ms p50=${p50.toFixed(1)} p95=${p95.toFixed(1)} max=${max.toFixed(1)}`);

  if (fail > 0) {
    throw new Error(`Load test finished with failures: fail=${fail}`);
  }
}

main().catch((err) => {
  console.error('[load] FAIL', err && err.stack ? err.stack : err);
  process.exit(1);
});

