/* Multiuser production readiness checks for current deployment strategy. */
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = process.cwd();
let hasFailure = false;

function fail(msg) {
  hasFailure = true;
  console.error(`[READINESS][FAIL] ${msg}`);
}

function warn(msg) {
  console.warn(`[READINESS][WARN] ${msg}`);
}

function ok(msg) {
  console.log(`[READINESS][OK] ${msg}`);
}

function readFile(file) {
  try {
    return fs.readFileSync(path.join(root, file), 'utf8');
  } catch (_) {
    return null;
  }
}

function findYamlValue(yaml, key) {
  const regex = new RegExp(`^\\s*${key}:\\s*\"([^\"]*)\"\\s*$`, 'm');
  const match = yaml.match(regex);
  return match ? String(match[1] || '').trim() : null;
}

function checkAppYamlStrategy() {
  const appYaml = readFile('app.yaml');
  if (!appYaml) {
    fail('app.yaml nao encontrado.');
    return;
  }

  const sensitiveDirectKeys = [
    'JWT_SECRET',
    'CONTA_AZUL_CLIENT_SECRET',
    'CONTA_AZUL_ACCESS_TOKEN',
    'CONTA_AZUL_REFRESH_TOKEN',
    'DATABASE_URL',
    'SIGNATURE_SECRET',
    'EVENT_WEBHOOK_SECRET'
  ];

  const exposed = [];
  for (const key of sensitiveDirectKeys) {
    const value = findYamlValue(appYaml, key);
    if (value && value.length > 0) exposed.push(key);
  }
  if (exposed.length > 0) {
    fail(`Segredos ainda hardcoded em app.yaml: ${exposed.join(', ')}`);
  } else {
    ok('Sem segredos hardcoded no app.yaml.');
  }

  const secretManagerEnabled = findYamlValue(appYaml, 'SECRET_MANAGER_ENABLED') === 'true';
  if (!secretManagerEnabled) {
    fail('SECRET_MANAGER_ENABLED precisa estar true no app.yaml para a estrategia atual.');
  } else {
    ok('Secret Manager habilitado no app.yaml.');
  }

  const requiredMapKeys = [
    'GCP_PROJECT_ID',
    'SECRET_JWT_SECRET',
    'SECRET_CONTA_AZUL_CLIENT_SECRET',
    'SECRET_CONTA_AZUL_ACCESS_TOKEN',
    'SECRET_CONTA_AZUL_REFRESH_TOKEN',
    'SECRET_DATABASE_URL',
    'SECRET_SIGNATURE_SECRET',
    'SECRET_EVENT_WEBHOOK_SECRET'
  ];
  const missing = requiredMapKeys.filter((k) => !findYamlValue(appYaml, k));
  if (missing.length) {
    fail(`Mapeamento de secrets ausente no app.yaml: ${missing.join(', ')}`);
  } else {
    ok('Mapeamento de nomes de secrets presente no app.yaml.');
  }
}

function checkSecretsWithGcloud() {
  if (process.env.VERIFY_GCLOUD_SECRETS !== 'true') {
    warn('Validacao remota de secrets desativada (defina VERIFY_GCLOUD_SECRETS=true para habilitar).');
    return;
  }

  const appYaml = readFile('app.yaml');
  if (!appYaml) {
    fail('app.yaml nao encontrado para validar secrets remotos.');
    return;
  }

  const projectId = findYamlValue(appYaml, 'GCP_PROJECT_ID');
  if (!projectId) {
    fail('GCP_PROJECT_ID ausente no app.yaml.');
    return;
  }

  const mappedNames = [
    findYamlValue(appYaml, 'SECRET_JWT_SECRET'),
    findYamlValue(appYaml, 'SECRET_CONTA_AZUL_CLIENT_SECRET'),
    findYamlValue(appYaml, 'SECRET_CONTA_AZUL_ACCESS_TOKEN'),
    findYamlValue(appYaml, 'SECRET_CONTA_AZUL_REFRESH_TOKEN'),
    findYamlValue(appYaml, 'SECRET_DATABASE_URL'),
    findYamlValue(appYaml, 'SECRET_SIGNATURE_SECRET'),
    findYamlValue(appYaml, 'SECRET_EVENT_WEBHOOK_SECRET')
  ].filter(Boolean);

  for (const secretName of mappedNames) {
    const result = spawnSync('gcloud', ['secrets', 'describe', secretName, `--project=${projectId}`], {
      cwd: root,
      encoding: 'utf8'
    });
    if (result.status !== 0) {
      fail(`Secret nao encontrado ou sem acesso: ${secretName}`);
    } else {
      ok(`Secret encontrado: ${secretName}`);
    }
  }
}

checkAppYamlStrategy();
checkSecretsWithGcloud();

if (hasFailure) {
  process.exit(1);
}

ok('Readiness check finalizado.');
