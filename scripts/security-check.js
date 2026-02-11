/* Phase 3 security preflight.
   Fails only on critical insecure defaults unless strict mode is enabled. */
const fs = require('fs');
const path = require('path');

const root = process.cwd();
const strictMode = process.env.SECURITY_GATE_STRICT === 'true';
let hasFailure = false;

function fail(msg) {
  hasFailure = true;
  console.error(`[SECURITY][FAIL] ${msg}`);
}

function warn(msg) {
  console.warn(`[SECURITY][WARN] ${msg}`);
}

function ok(msg) {
  console.log(`[SECURITY][OK] ${msg}`);
}

function readTextIfExists(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (_) {
    return null;
  }
}

function checkAppYaml() {
  const appYaml = readTextIfExists(path.join(root, 'app.yaml'));
  if (!appYaml) {
    warn('app.yaml nao encontrado. Pulando verificacao de segredos em app.yaml.');
    return;
  }

  const secretLikeKeys = [
    'JWT_SECRET',
    'CONTA_AZUL_CLIENT_SECRET',
    'CONTA_AZUL_ACCESS_TOKEN',
    'CONTA_AZUL_REFRESH_TOKEN',
    'DATABASE_URL',
    'SIGNATURE_SECRET',
    'EVENT_WEBHOOK_SECRET'
  ];

  for (const key of secretLikeKeys) {
    const regex = new RegExp(`^\\s*${key}:\\s*\"([^\"]*)\"\\s*$`, 'm');
    const match = appYaml.match(regex);
    if (!match) continue;
    const value = String(match[1] || '').trim();
    if (!value) {
      warn(`${key} vazio em app.yaml.`);
      continue;
    }
    if (key === 'SIGNATURE_SECRET' && value.toLowerCase() === 'change-me') {
      if (strictMode) {
        fail('SIGNATURE_SECRET esta com valor padrao inseguro (change-me).');
      } else {
        warn('SIGNATURE_SECRET esta com valor padrao inseguro (change-me).');
      }
      continue;
    }
    if (strictMode) {
      fail(`${key} parece estar hardcoded em app.yaml. Mova para Secret Manager.`);
    } else {
      warn(`${key} esta definido em app.yaml. Recomendado mover para Secret Manager.`);
    }
  }

  const missingSecretEnvKeys = secretLikeKeys.filter((key) => {
    const secretEnvRegex = new RegExp(`^\\s*${key}:\\s*projects\\/[^\\s]+\\/secrets\\/${key}\\/versions\\/latest\\s*$`, 'm');
    return !secretEnvRegex.test(appYaml);
  });

  if (missingSecretEnvKeys.length > 0) {
    const msg = `secret_env_variables ausente/incompleto para: ${missingSecretEnvKeys.join(', ')}`;
    if (strictMode) {
      fail(msg);
    } else {
      warn(msg);
    }
  } else {
    ok('secret_env_variables configurado para segredos criticos.');
  }
}

function checkDotEnvExample() {
  const envExample = readTextIfExists(path.join(root, '.env.example'));
  if (!envExample) {
    warn('.env.example nao encontrado.');
    return;
  }
  if (!envExample.includes('JWT_SECRET=')) {
    fail('.env.example sem chave JWT_SECRET.');
  } else {
    ok('JWT_SECRET presente em .env.example.');
  }
}

checkAppYaml();
checkDotEnvExample();

if (hasFailure) {
  process.exit(1);
}

ok(`Security preflight finalizado${strictMode ? ' (strict)' : ''}.`);
