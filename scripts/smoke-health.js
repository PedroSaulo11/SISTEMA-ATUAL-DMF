/* Starts the server and validates /api/health responds with HTTP 200. */
const { spawn } = require('child_process');
const http = require('http');

const PORT = process.env.PORT || '39123';
const HEALTH_TIMEOUT_MS = 15000;
const WAIT_BEFORE_CHECK_MS = 1500;
const MAX_ATTEMPTS = 10;
const RETRY_DELAY_MS = 1000;

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function fetchHealth() {
  return new Promise((resolve, reject) => {
    const req = http.get(`http://127.0.0.1:${PORT}/api/health`, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
    });
    req.on('error', reject);
    req.setTimeout(HEALTH_TIMEOUT_MS, () => {
      req.destroy(new Error('Health check timeout'));
    });
  });
}

async function main() {
  const child = spawn(process.execPath, ['server.js'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NODE_ENV: 'development',
      JWT_SECRET: process.env.JWT_SECRET || 'smoke-local-jwt-secret',
      PORT: String(PORT)
    }
  });

  let output = '';
  child.stdout.on('data', chunk => { output += chunk.toString(); });
  child.stderr.on('data', chunk => { output += chunk.toString(); });

  try {
    await wait(WAIT_BEFORE_CHECK_MS);
    let lastErr = null;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
      try {
        const res = await fetchHealth();
        if (res.statusCode !== 200) {
          throw new Error(`Health check retornou ${res.statusCode}: ${res.body}`);
        }
        console.log('[SMOKE][OK] /api/health respondeu 200');
        return;
      } catch (err) {
        lastErr = err;
        await wait(RETRY_DELAY_MS);
      }
    }
    throw lastErr || new Error('Health check falhou');
  } finally {
    if (!child.killed) {
      child.kill('SIGTERM');
    }
  }
}

main().catch((err) => {
  console.error('[SMOKE][FAIL]', err.message);
  process.exit(1);
});
