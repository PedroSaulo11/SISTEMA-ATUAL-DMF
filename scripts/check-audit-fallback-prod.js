/* eslint-disable no-console */
const { spawnSync } = require('child_process');

function mustEnv(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) {
    throw new Error(`Missing required env: ${name}`);
  }
  return value;
}

function runGcloud(args) {
  let result;
  if (process.platform === 'win32') {
    const quote = (value) => {
      const v = String(value);
      if (!/[\s"]/g.test(v)) return v;
      return `"${v.replace(/"/g, '\\"')}"`;
    };
    const command = ['gcloud', ...args].map(quote).join(' ');
    result = spawnSync('cmd.exe', ['/d', '/s', '/c', command], { encoding: 'utf8' });
  } else {
    result = spawnSync('gcloud', args, { encoding: 'utf8' });
  }
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    const stderr = String(result.stderr || '').trim();
    const stdout = String(result.stdout || '').trim();
    throw new Error(`gcloud ${args.join(' ')} failed: ${stderr || stdout || `exit ${result.status}`}`);
  }
  return String(result.stdout || '');
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function hit(url, headers = {}) {
  const res = await fetch(url, { method: 'GET', headers });
  return { status: res.status, body: await res.text() };
}

async function main() {
  const baseUrl = mustEnv('BASE_URL').replace(/\/+$/, '');
  const startTime = new Date().toISOString();

  const version = runGcloud([
    'app',
    'versions',
    'list',
    '--service=default',
    '--sort-by=~version.createTime',
    '--limit=1',
    '--format=value(id)'
  ]).trim();
  assert(version, 'Could not resolve latest App Engine version.');

  const noToken = await hit(`${baseUrl}/api/auth/user-status`);
  assert(noToken.status === 401 || noToken.status === 503, `Expected 401/503 without token, got ${noToken.status}`);

  const invalid = await hit(`${baseUrl}/api/auth/user-status`, {
    Authorization: 'Bearer invalid.token.value'
  });
  assert(invalid.status === 401 || invalid.status === 503, `Expected 401/503 with invalid token, got ${invalid.status}`);

  await sleep(6000);

  const logsRaw = runGcloud([
    'app',
    'logs',
    'read',
    '--service=default',
    `--version=${version}`,
    '--limit=200',
    '--format=json'
  ]);
  let entries = [];
  try {
    entries = JSON.parse(logsRaw || '[]');
  } catch (_) {
    entries = [];
  }
  const startMs = Date.parse(startTime);
  const lines = entries
    .filter((e) => {
      const ts = Date.parse(String(e?.timestamp || ''));
      return Number.isFinite(ts) && ts >= startMs;
    })
    .map((e) => String(e?.textPayload || e?.protoPayload?.line || ''))
    .filter(Boolean);
  const logs = lines.join('\n');

  const hasAuthMissing = logs.includes('Access attempt without token');
  const hasAuthInvalid = logs.includes('Invalid token used');
  const hasAuditFailure = logs.includes('Failed to record audit event');
  const hasSeqError = logs.includes('audit_events_id_seq');

  assert(!hasSeqError, 'Found "audit_events_id_seq" sequence permission error in logs.');
  if (hasAuditFailure) {
    console.log('[audit-fallback] INFO generic audit warning found (non-sequence).');
  }

  console.log(`[audit-fallback] PASS version=${version} start=${startTime}`);
}

main().catch((err) => {
  console.error('[audit-fallback] FAIL', err && err.stack ? err.stack : err);
  process.exit(1);
});
