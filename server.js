// In production (App Engine), config comes from env vars / Secret Manager.
// Loading `.env` in production can accidentally override secrets (e.g. DATABASE_URL).
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const winston = require('winston');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { withCache } = require('./cache');
const {
  initDb,
  isDbReady,
  getUserByUsernameOrEmail,
  getUserById,
  findUserByUsernameOrEmailExcludingId,
  createUser,
  updateUserById,
  deleteUserById,
  listUsers,
  replaceUsers,
  updateLastLogin,
  getServiceToken,
  upsertServiceToken,
  listFlowPayments,
  replaceFlowPayments,
  upsertFlowPayment,
  updateFlowPaymentWithVersion,
  updateFlowPayment,
  getFlowPaymentById,
  signFlowPaymentIfUnsigned,
  getMonthlyReport,
  listFlowArchives,
  createFlowArchive,
  deleteFlowArchive,
  replaceFlowArchives,
  listUserCompanies,
  replaceUserCompanies,
  listCenterCompanies,
  upsertCenterCompany,
  bulkUpsertCenterCompanies,
  listBudgetLimits,
  upsertBudgetLimits,
  insertBackupSnapshot,
  listBackupSnapshots,
  insertLoginAudit,
  listLoginAudits,
  insertAuditEvent,
  listAuditEvents,
  listRoles,
  getRoleByName,
  upsertRole,
  deleteRoleByName,
  replaceRoles,
  getUserSession,
  setUserSessionRevokedAfter,
  insertWebhook,
  validateDbSchema
} = require('./db');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3001;
const EXTERNAL_API_TIMEOUT_MS = Number(process.env.EXTERNAL_API_TIMEOUT_MS || 10000);
const CONTA_AZUL_TIMEOUT_MS = Number(process.env.CONTA_AZUL_TIMEOUT_MS || EXTERNAL_API_TIMEOUT_MS);
const COBLI_TIMEOUT_MS = Number(process.env.COBLI_TIMEOUT_MS || EXTERNAL_API_TIMEOUT_MS);
const SLOW_REQUEST_THRESHOLD_MS = Number(process.env.SLOW_REQUEST_THRESHOLD_MS || 2000);

function normalizeCompany(value) {
  const v = String(value || '').trim().toLowerCase();
  if (v === 'real energy' || v === 'real' || v === 'realenergy') return 'Real Energy';
  if (v === 'jfx') return 'JFX';
  if (v === 'dmf') return 'DMF';
  return value ? String(value).trim() : null;
}

function normalizeRole(value) {
  return String(value || '').trim().toLowerCase();
}

async function isAllowedRole(role) {
  if (role === undefined || role === null) return true;
  const normalized = normalizeRole(role);
  if (!normalized) return false;
  if (DEFAULT_ROLE_PERMISSIONS[normalized]) return true;
  if (!isDbReady()) return true;
  try {
    const roles = await listRoles();
    return roles.some(r => normalizeRole(r.name) === normalized);
  } catch (error) {
    return false;
  }
}

const PERMISSIONS_ENFORCED = process.env.PERMISSIONS_ENFORCED === 'true';
const ROLE_CACHE_TTL_MS = Number(process.env.ROLE_CACHE_TTL_MS || 30000);
const DEFAULT_ROLE_PERMISSIONS = {
  admin: [
    'admin_access',
    'audit_access',
    'audit_login_access',
    'sign_payments',
    'import_payments',
    'export_payments',
    'add_payments',
    'delete_payments',
    'view_archives',
    'archive_flow',
    'delete_archive',
    'export_archives',
    'compare_archives',
    'roles_manage',
    'user_manage',
    'backup_restore',
    'revoke_sessions'
  ],
  gestor: [
    'sign_payments',
    'import_payments',
    'export_payments',
    'add_payments',
    'view_archives',
    'compare_archives',
    'audit_access',
    'audit_login_access'
  ],
  user: ['sign_payments']
};
let roleCache = { data: {}, loadedAt: 0 };
const ENFORCE_COMPANY_ACCESS = process.env.ENFORCE_COMPANY_ACCESS === 'true';
const ALLOW_ALL_COMPANIES_WHEN_UNSET = process.env.ALLOW_ALL_COMPANIES_WHEN_UNSET !== 'false';
const DEFAULT_COMPANIES = String(process.env.DEFAULT_COMPANIES || 'DMF,JFX,Real Energy')
  .split(',')
  .map(s => normalizeCompany(s))
  .filter(Boolean);
const DEFAULT_COMPANIES_UNIQUE = Array.from(new Set(DEFAULT_COMPANIES));

function isAllowedCompany(company) {
  if (!company) return false;
  // When configured, only allow companies from this fixed allow-list.
  // This prevents `?company=` from becoming an unbounded tenant selector.
  if (DEFAULT_COMPANIES_UNIQUE.length) {
    return DEFAULT_COMPANIES_UNIQUE.includes(company);
  }
  return true;
}
const TOKEN_CACHE_TTL_MS = Number(process.env.TOKEN_CACHE_TTL_MS || 30000);
let lastTokenLoadAt = 0;
const CRON_SECRET = process.env.CRON_SECRET || '';
const DB_SCHEMA_STRICT = process.env.DB_SCHEMA_STRICT === 'true';
const runtimeStats = {
  conflictsTotal: 0,
  lastConflictAt: null
};

async function loadRolePermissions(role) {
  const normalized = normalizeRole(role);
  if (!isDbReady()) {
    return DEFAULT_ROLE_PERMISSIONS[normalized] || [];
  }
  const now = Date.now();
  if (!roleCache.loadedAt || now - roleCache.loadedAt > ROLE_CACHE_TTL_MS) {
    try {
      const roles = await listRoles();
      roleCache.data = roles.reduce((acc, r) => {
        acc[normalizeRole(r.name)] = Array.isArray(r.permissions) ? r.permissions : [];
        return acc;
      }, {});
      roleCache.loadedAt = now;
    } catch (error) {
      logger.warn('Failed to load roles from DB', { error: error.message });
      return DEFAULT_ROLE_PERMISSIONS[normalized] || [];
    }
  }
  return roleCache.data[normalized] || DEFAULT_ROLE_PERMISSIONS[normalized] || [];
}

async function hasPermission(role, permission) {
  const perms = await loadRolePermissions(role);
  return perms.includes('all') || perms.includes(permission);
}

async function resolveCompanyAccess(userId, role) {
  if (!ENFORCE_COMPANY_ACCESS) return null;
  if (!isDbReady()) return null;
  if (normalizeRole(role) === 'admin') return null;
  const companies = await listUserCompanies(userId);
  if (companies && companies.length) return companies;
  // If user access wasn't configured, fall back to a fixed default list
  // (prevents "company" query param from becoming an unbounded tenant selector).
  if (DEFAULT_COMPANIES_UNIQUE.length) return DEFAULT_COMPANIES_UNIQUE;
  return [];
}

async function enforceCompanyAccess(req, res, next) {
  if (!ENFORCE_COMPANY_ACCESS) return next();
  if (!isDbReady()) return next();
  const role = req.user?.role;
  const requestedRaw = req.query.company || req.body?.company;
  const requested = normalizeCompany(requestedRaw);
  if (requested && !isAllowedCompany(requested)) {
    await recordAuditEvent(req, 'COMPANY_ACCESS_DENIED', `Empresa nao permitida: ${requested}.`, {
      company: requested
    });
    return res.status(403).json({ error: 'Company not allowed' });
  }
  if (normalizeRole(role) === 'admin') return next();
  const companies = await resolveCompanyAccess(req.user?.id, role);
  if (!companies || companies.length === 0) {
    if (ALLOW_ALL_COMPANIES_WHEN_UNSET) {
      return next();
    }
    await recordAuditEvent(req, 'COMPANY_ACCESS_DENIED', 'Nenhuma empresa liberada para o usuário.', {
      userId: req.user?.id || null
    });
    return res.status(403).json({ error: 'Company access not configured' });
  }
  if (!requestedRaw) {
    return next();
  }
  if (!requested) {
    return next();
  }
  if (!companies.includes(requested)) {
    await recordAuditEvent(req, 'COMPANY_ACCESS_DENIED', `Acesso negado para ${requested}.`, {
      company: requested
    });
    return res.status(403).json({ error: 'Company access denied' });
  }
  return next();
}

function requireCompanyParam(req, res, next) {
  if (!ENFORCE_COMPANY_ACCESS) return next();
  const company = normalizeCompany(req.query.company || req.body?.company);
  if (!company) return res.status(400).json({ error: 'Company required' });
  if (!isAllowedCompany(company)) return res.status(403).json({ error: 'Company not allowed' });
  return next();
}

async function recordAuditEvent(req, action, details, metadata = null) {
  if (!isDbReady()) return;
  try {
    await insertAuditEvent({
      action,
      details,
      username: req.user?.username || null,
      userId: req.user?.id || null,
      ip: req.ip,
      userAgent: req.headers['user-agent'] || null,
      metadata: metadata && typeof metadata === 'object' ? metadata : null
    });
  } catch (error) {
    logger.warn('Failed to record audit event', { action, error: error.message });
  }
}

function respondConflict(req, res, { code, message, payload = null, metadata = null }) {
  const safeCode = String(code || 'CONFLICT');
  const safeMessage = String(message || 'Conflict');
  runtimeStats.conflictsTotal += 1;
  runtimeStats.lastConflictAt = new Date().toISOString();
  logger.warn('ALERT_CONFLICT', {
    request_id: req.requestId || null,
    code: safeCode,
    message: safeMessage,
    path: req.path,
    method: req.method,
    user: req.user?.username || null,
    metadata: metadata || null
  });
  recordAuditEvent(req, safeCode, safeMessage, metadata || null).catch(() => {});
  return res.status(409).json({
    error: 'Conflict',
    code: safeCode,
    message: safeMessage,
    ...(payload && typeof payload === 'object' ? payload : {})
  });
}

const contaAzulClient = axios.create({ timeout: CONTA_AZUL_TIMEOUT_MS });
const cobliClient = axios.create({ timeout: COBLI_TIMEOUT_MS });

// Security: Configure Winston logger
function isGcpRuntime() {
  // Covers App Engine / Cloud Run style env vars.
  return !!(process.env.GAE_ENV || process.env.K_SERVICE || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT);
}

const enableConsoleLogs = process.env.LOG_TO_CONSOLE === 'true' || process.env.NODE_ENV !== 'production' || isGcpRuntime();
const loggerTransports = [];

if (enableConsoleLogs) {
  loggerTransports.push(new winston.transports.Console({
    format: winston.format.simple(),
  }));
} else {
  // File transport is unsafe on App Engine because the filesystem is not guaranteed writable.
  // Keep it for local/server deployments where the working directory is writable.
  const logDir = path.join(__dirname, 'logs');
  fs.mkdirSync(logDir, { recursive: true });
  loggerTransports.push(new winston.transports.File({ filename: path.join(logDir, 'error.log'), level: 'error' }));
  loggerTransports.push(new winston.transports.File({ filename: path.join(logDir, 'combined.log') }));
}

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'dmf-system' },
  transports: loggerTransports,
});

// Optional resource monitoring
if (process.env.MONITOR_ENABLED === 'true') {
  const intervalMs = Number(process.env.MONITOR_INTERVAL_MS || 60000);
  setInterval(() => {
    const mem = process.memoryUsage();
    const cpu = process.cpuUsage();
    logger.info('Resource usage', {
      rss: mem.rss,
      heap_used: mem.heapUsed,
      heap_total: mem.heapTotal,
      external: mem.external,
      cpu_user: cpu.user,
      cpu_system: cpu.system
    });
  }, intervalMs).unref();
}

// Security: Rate limiting
const API_RATE_LIMIT_WINDOW_MS = Number(process.env.API_RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000);
const API_RATE_LIMIT_MAX = Number(process.env.API_RATE_LIMIT_MAX || 600);
const limiter = rateLimit({
  windowMs: API_RATE_LIMIT_WINDOW_MS, // 15 minutes default
  max: API_RATE_LIMIT_MAX, // limit each IP to N requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Security: Auth rate limiting (stricter)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: Number(process.env.AUTH_RATE_LIMIT_MAX || 5), // limit each IP to N auth attempts per windowMs
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Security: Critical operation rate limiting
const criticalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: Number(process.env.CRITICAL_RATE_LIMIT_MAX || 20),
  message: 'Too many critical requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const importLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.IMPORT_RATE_LIMIT_MAX || 30),
  message: 'Too many import requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Security: Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net", "https://unpkg.com"],
      styleSrcAttr: ["'unsafe-inline'"],
      scriptSrc: ["'self'", "https://cdn.jsdelivr.net", "https://unpkg.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://cdn.jsdelivr.net", "https://unpkg.com"],
    },
  },
}));

// Security: Apply rate limiting
app.use('/api/', limiter);
app.use('/api/auth/', authLimiter);

// Security: CORS configuration
const corsOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map(origin => origin.trim()).filter(Boolean)
  : (process.env.NODE_ENV === 'production' ? [] : ['http://localhost:3000', 'http://localhost:3001']);

app.use(cors({
  origin: corsOrigins.length ? corsOrigins : false,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-CSRF-Token'],
}));

// Correlation id for tracing requests across logs and clients.
app.use((req, res, next) => {
  const headerId = req.get('X-Request-Id');
  const requestId = headerId && String(headerId).trim() ? String(headerId).trim() : crypto.randomUUID();
  req.requestId = requestId;
  res.setHeader('X-Request-Id', requestId);
  next();
});

// Monitoring: request timing and 5xx alerts
app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  res.on('finish', () => {
    const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
    if (res.statusCode >= 500) {
      logger.error('ALERT_HTTP_5XX', {
        request_id: req.requestId || null,
        method: req.method,
        path: req.originalUrl,
        status: res.statusCode,
        duration_ms: Math.round(elapsedMs)
      });
    } else if (elapsedMs >= SLOW_REQUEST_THRESHOLD_MS) {
      logger.warn('ALERT_SLOW_REQUEST', {
        request_id: req.requestId || null,
        method: req.method,
        path: req.originalUrl,
        status: res.statusCode,
        duration_ms: Math.round(elapsedMs)
      });
    }
  });
  next();
});

// Middleware
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// Serve static files (allowlist only)
const PUBLIC_FILES = new Set([
  'index.html',
  'dashboard.html',
  'payments.html',
  'audit.html',
  'admin.html',
  'assistente.html',
  'cobli.html',
  'dashboard.fragment.html',
  'payments.fragment.html',
  'audit.fragment.html',
  'admin.fragment.html',
  'assistente.fragment.html',
  'cobli.fragment.html',
  'style.css',
  'bootstrap.js',
  'script.js',
  'assistant.js',
  'assistant.css',
  'verify.html',
  'verify.js',
  'verify.css'
]);

// Boot gating:
// Keep the process alive (so App Engine doesn't show a generic 503) and return explicit 503s for API/tasks
// until required secrets/config are loaded. Static UI can still load to surface diagnostics via /api/health.
const bootState = {
  ready: false,
  startedAt: new Date().toISOString(),
  fatalError: null,
};

function shouldExposeStartupError() {
  return process.env.EXPOSE_STARTUP_ERRORS === 'true' || process.env.NODE_ENV !== 'production';
}

app.use((req, res, next) => {
  if (bootState.ready) return next();

  // Allow health and static UI while booting.
  if (req.path === '/api/health') return next();
  if (req.path === '/' || req.path === '/verify') return next();
  if (req.path.startsWith('/assets/')) return next();
  const candidate = req.path.startsWith('/') ? req.path.slice(1) : req.path;
  if (PUBLIC_FILES.has(candidate)) return next();

  // Gate API + cron/tasks until boot is ready.
  if (req.path.startsWith('/api') || req.path.startsWith('/tasks')) {
    const payload = { error: 'Service initializing' };
    if (bootState.fatalError && shouldExposeStartupError()) {
      payload.details = bootState.fatalError;
    }
    return res.status(503).json(payload);
  }

  return next();
});

app.use('/assets', express.static(path.join(__dirname, 'assets')));

// Explicit favicon route (App Engine won't serve arbitrary root files unless we do).
app.get('/favicon.ico', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.sendFile(path.join(__dirname, 'favicon.ico'));
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/verify', (req, res) => {
  res.sendFile(path.join(__dirname, 'verify.html'));
});

app.get('/:file', (req, res) => {
  const file = req.params.file;
  if (!PUBLIC_FILES.has(file)) {
    return res.status(404).end();
  }
  res.sendFile(path.join(__dirname, file));
});

// Token storage (persisted in database)
let accessToken = null;
let refreshToken = null;
let tokenExpiry = null; // Will be set based on JWT expiry
const users = []; // In-memory fallback for transition
let JWT_SECRET = null;

// OAuth2 Configuration
let CLIENT_ID = null;
let CLIENT_SECRET = null;
let TOKEN_URL = null;
let CONTA_AZUL_API_BASE_URL = null;
let CONTA_AZUL_PAYMENTS_PATH = null;
let SIGNATURE_SECRET = null;

// Cobli Configuration
let COBLI_API_BASE_URL = null;
let COBLI_API_TOKEN = null;
let COBLI_AUTH_HEADER = null;
let COBLI_AUTH_SCHEME = null;
let COBLI_WEBHOOK_SECRET = null;
let COBLI_WEBHOOK_SIGNATURE_HEADER = null;
let EVENT_WEBHOOK_URL = '';
let EVENT_WEBHOOK_SECRET = '';

function applyRuntimeConfigFromEnv() {
  JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV === 'production' ? null : 'dev-insecure-jwt-secret');
  CLIENT_ID = process.env.CONTA_AZUL_CLIENT_ID || null;
  CLIENT_SECRET = process.env.CONTA_AZUL_CLIENT_SECRET || null;
  TOKEN_URL = process.env.CONTA_AZUL_TOKEN_URL || null;
  CONTA_AZUL_API_BASE_URL = process.env.CONTA_AZUL_API_BASE_URL || 'https://api.contaazul.com';
  CONTA_AZUL_PAYMENTS_PATH = process.env.CONTA_AZUL_PAYMENTS_PATH || '/v2/payments';
  SIGNATURE_SECRET = process.env.SIGNATURE_SECRET || (process.env.NODE_ENV === 'production' ? null : 'dev-insecure-signature-secret');
  COBLI_API_BASE_URL = process.env.COBLI_API_BASE_URL || null;
  COBLI_API_TOKEN = process.env.COBLI_API_TOKEN || null;
  COBLI_AUTH_HEADER = process.env.COBLI_AUTH_HEADER || 'Authorization';
  COBLI_AUTH_SCHEME = process.env.COBLI_AUTH_SCHEME || 'Bearer';
  COBLI_WEBHOOK_SECRET = process.env.COBLI_WEBHOOK_SECRET || null;
  COBLI_WEBHOOK_SIGNATURE_HEADER = process.env.COBLI_WEBHOOK_SIGNATURE_HEADER || null;
  EVENT_WEBHOOK_URL = process.env.EVENT_WEBHOOK_URL || '';
  EVENT_WEBHOOK_SECRET = process.env.EVENT_WEBHOOK_SECRET || '';
}

function describeDatabaseUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return { configured: false };
  const usesCloudSqlSocket = raw.includes('/cloudsql/');
  const hostHint = usesCloudSqlSocket ? '/cloudsql/...' : (raw.match(/@([^/?]+)/)?.[1] || null);
  return {
    configured: true,
    uses_cloudsql_socket: usesCloudSqlSocket,
    host_hint: hostHint
  };
}

async function loadSecretsFromSecretManager() {
  const enabled = process.env.SECRET_MANAGER_ENABLED === 'true';
  if (!enabled) return;

  const projectId = process.env.GCP_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;
  if (!projectId) {
    throw new Error('SECRET_MANAGER_ENABLED=true but project id not found (GCP_PROJECT_ID/GOOGLE_CLOUD_PROJECT).');
  }

  const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
  const client = new SecretManagerServiceClient();
  const mappings = [
    { envVar: 'JWT_SECRET', secretName: process.env.SECRET_JWT_SECRET || 'JWT_SECRET', required: true },
    // Optional: system must boot even if Conta Azul integration is not configured.
    { envVar: 'CONTA_AZUL_CLIENT_SECRET', secretName: process.env.SECRET_CONTA_AZUL_CLIENT_SECRET || 'CONTA_AZUL_CLIENT_SECRET', required: false },
    { envVar: 'CONTA_AZUL_ACCESS_TOKEN', secretName: process.env.SECRET_CONTA_AZUL_ACCESS_TOKEN || 'CONTA_AZUL_ACCESS_TOKEN', required: false },
    { envVar: 'CONTA_AZUL_REFRESH_TOKEN', secretName: process.env.SECRET_CONTA_AZUL_REFRESH_TOKEN || 'CONTA_AZUL_REFRESH_TOKEN', required: false },
    { envVar: 'DATABASE_URL', secretName: process.env.SECRET_DATABASE_URL || 'DATABASE_URL', required: true },
    { envVar: 'SIGNATURE_SECRET', secretName: process.env.SECRET_SIGNATURE_SECRET || 'SIGNATURE_SECRET', required: true },
    { envVar: 'EVENT_WEBHOOK_SECRET', secretName: process.env.SECRET_EVENT_WEBHOOK_SECRET || 'EVENT_WEBHOOK_SECRET', required: false },
    { envVar: 'COBLI_API_TOKEN', secretName: process.env.SECRET_COBLI_API_TOKEN || 'COBLI_API_TOKEN', required: false }
  ];

  const missing = [];
  for (const item of mappings) {
    if (process.env[item.envVar]) continue;
    try {
      const name = `projects/${projectId}/secrets/${item.secretName}/versions/latest`;
      const [version] = await client.accessSecretVersion({ name });
      const payload = version?.payload?.data ? version.payload.data.toString('utf8').trim() : '';
      if (payload) {
        process.env[item.envVar] = payload;
      } else if (item.required) {
        missing.push(item.envVar);
      }
    } catch (error) {
      if (item.required) {
        logger.error('Required secret not loaded from Secret Manager', {
          envVar: item.envVar,
          secretName: item.secretName,
          error: error.message
        });
        missing.push(item.envVar);
      } else {
        logger.warn('Optional secret not loaded from Secret Manager', {
          envVar: item.envVar,
          secretName: item.secretName,
          error: error.message
        });
      }
    }
  }

  if (missing.length) {
    throw new Error(`Required secrets missing: ${missing.join(', ')}`);
  }

  logger.info('Secrets loaded from Secret Manager', {
    projectId,
    loaded: mappings.map(m => m.envVar).filter(envVar => !!process.env[envVar]).length
  });
}

applyRuntimeConfigFromEnv();

async function emitEventWebhook(eventType, payload = {}) {
  if (!EVENT_WEBHOOK_URL) return;
  try {
    const body = { event: eventType, timestamp: new Date().toISOString(), payload };
    const headers = { 'Content-Type': 'application/json' };
    if (EVENT_WEBHOOK_SECRET) {
      const signature = crypto.createHmac('sha256', EVENT_WEBHOOK_SECRET)
        .update(JSON.stringify(body))
        .digest('hex');
      headers['X-DMF-Signature'] = signature;
    }
    await axios.post(EVENT_WEBHOOK_URL, body, { headers, timeout: 5000 });
  } catch (error) {
    logger.warn('Event webhook failed', { eventType, error: error.message });
  }
}

function computeChainHash({ prevHash, payment }) {
  if (!SIGNATURE_SECRET) return null;
  const payload = [
    prevHash || '',
    payment?.id || '',
    payment?.assinatura?.hash || '',
    String(payment?.valor ?? ''),
    String(payment?.centro ?? ''),
    payment?.assinatura?.dataISO || ''
  ].join('|');
  return crypto.createHmac('sha256', SIGNATURE_SECRET).update(payload).digest('hex');
}

function applyChainHashes(payments = []) {
  const ordered = [...payments].sort((a, b) => {
    const ad = new Date(a.created_at || 0).getTime();
    const bd = new Date(b.created_at || 0).getTime();
    if (ad !== bd) return ad - bd;
    return String(a.id).localeCompare(String(b.id));
  });
  let prevHash = '';
  return ordered.map(p => {
    if (p && p.assinatura) {
      const chainHash = computeChainHash({ prevHash, payment: p });
      const assinatura = { ...p.assinatura, chain_hash: chainHash };
      prevHash = chainHash || prevHash;
      return { ...p, assinatura };
    }
    return p;
  });
}

function buildCobliHeaders(extraHeaders = {}) {
  if (!COBLI_API_TOKEN) {
    throw new Error('COBLI_API_TOKEN is not configured');
  }

  const headers = {
    ...extraHeaders
  };

  const headerValue = COBLI_AUTH_SCHEME
    ? `${COBLI_AUTH_SCHEME} ${COBLI_API_TOKEN}`
    : COBLI_API_TOKEN;

  headers[COBLI_AUTH_HEADER] = headerValue;
  return headers;
}

function verifyCobliSignature(req) {
  if (!COBLI_WEBHOOK_SECRET || !COBLI_WEBHOOK_SIGNATURE_HEADER) {
    return true;
  }

  const signature = req.get(COBLI_WEBHOOK_SIGNATURE_HEADER);
  if (!signature) {
    return false;
  }

  if (!req.rawBody) {
    return false;
  }

  const rawBody = req.rawBody;
  const expected = crypto
    .createHmac('sha256', COBLI_WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');

  const normalizedSignature = signature.startsWith('sha256=')
    ? signature.slice('sha256='.length)
    : signature;

  if (normalizedSignature.length !== expected.length) {
    return false;
  }

  try {
    return crypto.timingSafeEqual(
      Buffer.from(normalizedSignature, 'hex'),
      Buffer.from(expected, 'hex')
    );
  } catch (error) {
    return false;
  }
}

async function cobliRequest(method, path, options = {}) {
  if (!COBLI_API_BASE_URL) {
    throw new Error('COBLI_API_BASE_URL is not configured');
  }

  const url = `${COBLI_API_BASE_URL.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
  const headers = buildCobliHeaders(options.headers || {});

  return cobliClient({
    method,
    url,
    headers,
    params: options.params,
    data: options.data
  });
}

// Function to decode JWT and get expiry
function decodeJwtPayload(token) {
  try {
    const base64Url = token.split('.')[1];
    if (!base64Url) return null;
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
    const json = Buffer.from(padded, 'base64').toString('utf8');
    return JSON.parse(json);
  } catch (error) {
    return null;
  }
}

function getTokenExpiry(token) {
  const payload = decodeJwtPayload(token);
  if (!payload || typeof payload.exp !== 'number') {
    return null;
  }
  return payload.exp * 1000; // Convert to milliseconds
}

function sanitizeUserForResponse(user) {
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    name: user.name || null,
    created_at: user.created_at,
    last_login: user.last_login
  };
}

async function loadTokensFromDb() {
  if (!isDbReady()) {
    accessToken = process.env.CONTA_AZUL_ACCESS_TOKEN || null;
    refreshToken = process.env.CONTA_AZUL_REFRESH_TOKEN || null;
    tokenExpiry = accessToken ? getTokenExpiry(accessToken) : null;
    return;
  }

  try {
    const tokenRow = await getServiceToken('conta_azul');
    if (tokenRow) {
      accessToken = tokenRow.access_token || null;
      refreshToken = tokenRow.refresh_token || null;
      tokenExpiry = tokenRow.expires_at ? new Date(tokenRow.expires_at).getTime() : null;
      if (accessToken && !tokenExpiry) {
        tokenExpiry = getTokenExpiry(accessToken);
      }
    } else {
      accessToken = process.env.CONTA_AZUL_ACCESS_TOKEN || null;
      refreshToken = process.env.CONTA_AZUL_REFRESH_TOKEN || null;
      tokenExpiry = accessToken ? getTokenExpiry(accessToken) : null;

      if (accessToken || refreshToken) {
        await upsertServiceToken(
          'conta_azul',
          accessToken,
          refreshToken,
          tokenExpiry ? new Date(tokenExpiry) : null
        );
      }
    }
  } catch (error) {
    logger.warn('Token load failed, using env fallback', { error: error.message });
    accessToken = process.env.CONTA_AZUL_ACCESS_TOKEN || null;
    refreshToken = process.env.CONTA_AZUL_REFRESH_TOKEN || null;
    tokenExpiry = accessToken ? getTokenExpiry(accessToken) : null;
  }
}

// Function to refresh token
async function refreshAccessToken() {
  if (!refreshToken) {
    throw new Error('No refresh token available');
  }

  try {
    const authHeader = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

    const response = await contaAzulClient.post(TOKEN_URL, new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    }), {
      headers: {
        'Authorization': `Basic ${authHeader}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    accessToken = response.data.access_token;
    refreshToken = response.data.refresh_token;
    tokenExpiry = Date.now() + (response.data.expires_in * 1000);

    if (isDbReady()) {
      await upsertServiceToken(
        'conta_azul',
        accessToken,
        refreshToken,
        tokenExpiry ? new Date(tokenExpiry) : null
      );
    }

    logger.info('Token refreshed successfully');
  } catch (error) {
    logger.error('Error refreshing token', { error: error.response?.data || error.message });
    // Reset tokens on failure
    accessToken = null;
    refreshToken = null;
    tokenExpiry = null;
    throw error;
  }
}

// Middleware to check and refresh token if needed
async function ensureValidToken() {
  const now = Date.now();
  if (isDbReady() && (!lastTokenLoadAt || now - lastTokenLoadAt > TOKEN_CACHE_TTL_MS)) {
    await loadTokensFromDb();
    lastTokenLoadAt = now;
  }
  if (!accessToken || !tokenExpiry) {
    await loadTokensFromDb();
    lastTokenLoadAt = Date.now();
  }

  if (accessToken && !tokenExpiry) {
    tokenExpiry = getTokenExpiry(accessToken);
  }

  if (!accessToken || !tokenExpiry) {
    if (refreshToken) {
      await refreshAccessToken();
    } else {
      throw new Error('No access token available. Please authenticate first.');
    }
  }

  if (Date.now() >= tokenExpiry - 60000) { // Refresh 1 minute before expiry
    await refreshAccessToken();
  }
}

async function contaAzulRequest(config, context = {}) {
  await ensureValidToken();
  const requestConfig = {
    ...config,
    headers: {
      ...(config.headers || {}),
      'Authorization': `Bearer ${accessToken}`
    }
  };

  try {
    return await contaAzulClient(requestConfig);
  } catch (error) {
    const status = error.response?.status;
    if ((status === 401 || status === 403) && refreshToken) {
      logger.warn('Conta Azul token invalid, attempting refresh', {
        status,
        ...context
      });
      await refreshAccessToken();
      const retryConfig = {
        ...config,
        headers: {
          ...(config.headers || {}),
          'Authorization': `Bearer ${accessToken}`
        }
      };
      return contaAzulClient(retryConfig);
    }
    throw error;
  }
}

function logTimeout(error, context) {
  if (error && error.code === 'ECONNABORTED') {
    logger.warn('External API timeout', { ...context, timeout_ms: context.timeout_ms });
  }
}

// Security: Input validation middleware
const { body, param, query, validationResult } = require('express-validator');

function validateRequest(validations) {
  return async (req, res, next) => {
    await Promise.all(validations.map(v => v.run(req)));
    const errors = validationResult(req);
    if (errors.isEmpty()) return next();
    logger.warn('Validation failed', { path: req.path, errors: errors.array() });
    await recordAuditEvent(req, 'VALIDATION_FAILED', `Validation failed for ${req.path}`, { errors: errors.array() });
    return res.status(400).json({ errors: errors.array() });
  };
}

// Security: Authentication middleware
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    logger.warn('Access attempt without token', { ip: req.ip, path: req.path });
    await recordAuditEvent(req, 'AUTH_MISSING_TOKEN', `Missing token for ${req.path}`);
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    if (isDbReady()) {
      const session = await getUserSession(user.id);
      if (session?.revoked_after) {
        const iatMs = (user.iat || 0) * 1000;
        if (iatMs && iatMs < new Date(session.revoked_after).getTime()) {
          await recordAuditEvent(req, 'AUTH_REVOKED', `Session revoked for ${req.path}`);
          return res.status(403).json({ error: 'Session revoked' });
        }
      }
      const dbUser = await getUserById(user.id);
      if (!dbUser) {
        await recordAuditEvent(req, 'AUTH_USER_NOT_FOUND', `User not found for ${req.path}`);
        return res.status(403).json({ error: 'User not found' });
      }
    }
    req.user = user;
    next();
  } catch (err) {
    logger.warn('Invalid token used', { error: err.message, ip: req.ip });
    await recordAuditEvent(req, 'AUTH_INVALID_TOKEN', `Invalid token for ${req.path}`);
    // Invalid/expired tokens should be 401 (session expired). 403 is reserved for valid tokens without access.
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// SSE auth: allow token via query param to support EventSource
async function authenticateTokenFromQuery(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = (authHeader && authHeader.split(' ')[1]) || req.query?.token || req.query?.access_token;
  if (!token) {
    logger.warn('Access attempt without token', { ip: req.ip, path: req.path });
    await recordAuditEvent(req, 'AUTH_MISSING_TOKEN', `Missing token for ${req.path}`);
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const user = jwt.verify(String(token), JWT_SECRET);
    if (isDbReady()) {
      const session = await getUserSession(user.id);
      if (session?.revoked_after) {
        const iatMs = (user.iat || 0) * 1000;
        if (iatMs && iatMs < new Date(session.revoked_after).getTime()) {
          await recordAuditEvent(req, 'AUTH_REVOKED', `Session revoked for ${req.path}`);
          return res.status(403).json({ error: 'Session revoked' });
        }
      }
      const dbUser = await getUserById(user.id);
      if (!dbUser) {
        await recordAuditEvent(req, 'AUTH_USER_NOT_FOUND', `User not found for ${req.path}`);
        return res.status(403).json({ error: 'User not found' });
      }
    }
    req.user = user;
    next();
  } catch (err) {
    logger.warn('Invalid token used', { error: err.message, ip: req.ip });
    await recordAuditEvent(req, 'AUTH_INVALID_TOKEN', `Invalid token for ${req.path}`);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Flow payment push notifications (SSE)
const flowSubscribers = new Set();
function notifyFlowSubscribers(company, payload) {
  const data = JSON.stringify(payload || {});
  for (const sub of flowSubscribers) {
    if (sub.company && company && sub.company !== company) continue;
    try {
      sub.res.write(`event: flow_update\n`);
      sub.res.write(`data: ${data}\n\n`);
    } catch (_) {
      // ignore broken stream
    }
  }
}

// NOTE: authenticateTokenFromQuery is defined once above. (Previously duplicated during refactor.)

// Security: Role-based authorization middleware
function authorizeRole(requiredRole) {
  return (req, res, next) => {
    if (!req.user) {
      logger.warn('Authorization check without authenticated user', { ip: req.ip });
      return res.status(401).json({ error: 'Authentication required' });
    }

    const roleHierarchy = { 'user': 1, 'gestor': 2, 'admin': 3 };
    const normalizedUserRole = normalizeRole(req.user.role);
    const normalizedRequired = normalizeRole(requiredRole);
    const userRoleLevel = roleHierarchy[normalizedUserRole] || 1;
    const requiredRoleLevel = roleHierarchy[normalizedRequired] || 1;

    if (userRoleLevel < requiredRoleLevel) {
      logger.warn('Insufficient permissions', {
        user: req.user.username,
        userRole: req.user.role,
        requiredRole,
        ip: req.ip,
        path: req.path
      });
      recordAuditEvent(req, 'AUTHZ_DENIED', `Missing role ${requiredRole}`, {
        requiredRole,
        userRole: req.user.role
      }).catch(() => {});
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
}

function authorizePermission(permission) {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const allowed = await hasPermission(req.user.role, permission);
    if (!allowed) {
      logger.warn('Permission denied', {
        user: req.user.username,
        permission,
        role: req.user.role,
        ip: req.ip,
        path: req.path
      });
      recordAuditEvent(req, 'PERMISSION_DENIED', `Missing permission ${permission}`, {
        permission,
        role: req.user.role
      }).catch(() => {});
      if (PERMISSIONS_ENFORCED) {
        return res.status(403).json({ error: 'Insufficient permissions' });
      }
    }
    return next();
  };
}

// Security: Authentication routes
app.post('/api/auth/register', [
  body('username').isLength({ min: 3, max: 50 }).trim().escape().withMessage('Username must be 3-50 characters'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('role').optional().custom(isAllowedRole).withMessage('Invalid role'),
  body('name').optional().isLength({ min: 2, max: 100 }).trim().escape(),
], async (req, res) => {
  try {
    // In production, avoid leaving public self-registration enabled.
    // To bootstrap the very first admin, allow registration only when DB is ready and empty.
    // After bootstrap, allow admin-created users even when public registration is disabled.
    if (process.env.NODE_ENV === 'production' && process.env.ALLOW_PUBLIC_REGISTER !== 'true') {
      if (!isDbReady()) {
        return res.status(503).json({ error: 'Database not ready' });
      }
      const existing = await listUsers();
      if (existing.length > 0) {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (!token) {
          return res.status(403).json({ error: 'Registration disabled' });
        }
        try {
          const authUser = jwt.verify(token, JWT_SECRET);
          const authRole = String(authUser?.role || '').trim().toLowerCase();
          if (authRole !== 'admin') {
            return res.status(403).json({ error: 'Registration disabled' });
          }
        } catch (_) {
          return res.status(403).json({ error: 'Registration disabled' });
        }
      }
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Registration validation failed', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password, role } = req.body;
    const normalizedUsername = String(username || '').trim();
    const normalizedEmail = String(email || '').trim().toLowerCase();
    const requestedRole = String(role || '').trim().toLowerCase();
    let assignedRole = 'user';

    if (requestedRole && requestedRole !== 'user') {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];
      if (!token) {
        return res.status(403).json({ error: 'Admin role required to set role' });
      }
      try {
        const authUser = jwt.verify(token, JWT_SECRET);
        const authRole = String(authUser?.role || '').trim().toLowerCase();
        if (authRole !== 'admin') {
          return res.status(403).json({ error: 'Admin role required to set role' });
        }
        assignedRole = requestedRole;
      } catch (err) {
        return res.status(403).json({ error: 'Admin role required to set role' });
      }
    }

    // Check if user already exists
    let existingUser = users.find(u =>
      String(u.username || '').toLowerCase() === normalizedUsername.toLowerCase() ||
      String(u.email || '').toLowerCase() === normalizedEmail.toLowerCase()
    );
    if (!existingUser && isDbReady()) {
      existingUser = await getUserByUsernameOrEmail(normalizedUsername) || await getUserByUsernameOrEmail(normalizedEmail);
    }
    if (existingUser) {
      logger.warn('Registration attempt with existing user', { username, email });
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    let newUser = null;
    if (isDbReady()) {
      newUser = await createUser({
        username: normalizedUsername,
        email: normalizedEmail,
        passwordHash: hashedPassword,
        role: assignedRole,
        name: req.body.name || null
      });
    }

    const fallbackUser = {
      id: newUser?.id || Date.now().toString(),
      username: normalizedUsername,
      email: normalizedEmail,
      password_hash: hashedPassword,
      role: assignedRole,
      name: req.body.name || null,
      created_at: new Date().toISOString(),
      last_login: null
    };
    users.push(fallbackUser);

    logger.info('User registered successfully', { username, email, role: (newUser?.role || fallbackUser.role) });
    emitEventWebhook('user_created', {
      userId: newUser?.id || fallbackUser.id,
      username: normalizedUsername,
      role: newUser?.role || fallbackUser.role
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: sanitizeUserForResponse(newUser || fallbackUser)
    });
  } catch (error) {
    logger.error('Registration error', { error: error.message });
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', [
  body('username').notEmpty().trim().escape().withMessage('Username required'),
  body('password').notEmpty().withMessage('Password required'),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Login validation failed', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const loginValue = String(username || '').trim();

    let user = users.find(u =>
      String(u.username || '').toLowerCase() === loginValue.toLowerCase() ||
      String(u.email || '').toLowerCase() === loginValue.toLowerCase()
    );
    if (!user && isDbReady()) {
      user = await getUserByUsernameOrEmail(loginValue);
    }
    if (!user) {
      if (isDbReady()) {
        insertLoginAudit({
          username: loginValue,
          ip: req.ip,
          success: false,
          details: 'Usuario nao encontrado'
        }).catch(() => {});
      }
      logger.warn('Login attempt with non-existent user', { username });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      if (isDbReady()) {
        insertLoginAudit({
          username: user.username,
          ip: req.ip,
          success: false,
          details: 'Senha invalida'
        }).catch(() => {});
      }
      logger.warn('Login attempt with wrong password', { username });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    if (isDbReady()) {
      await updateLastLogin(user.id);
      insertLoginAudit({
        username: user.username,
        ip: req.ip,
        success: true,
        details: 'Login ok'
      }).catch(() => {});
    }
    user.last_login = new Date().toISOString();

    // Generate JWT
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email, role: user.role, name: user.name || null },
      JWT_SECRET,
      { expiresIn: '48h' }
    );

    logger.info('User logged in successfully', { username, role: user.role });

    const permissions = await loadRolePermissions(user.role);

    res.json({
      message: 'Login successful',
      token,
      user: {
        ...sanitizeUserForResponse(user),
        permissions
      }
    });
  } catch (error) {
    logger.error('Login error', { error: error.message });
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/audit/logins', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const items = await listLoginAudits(200);
    res.json({ items });
  } catch (error) {
    logger.error('Error listing login audits', { error: error.message });
    res.status(500).json({ error: 'Failed to list login audits' });
  }
});

app.post('/api/audit/events', authenticateToken, authorizeRole('user'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const action = String(req.body?.action || '').trim();
    if (!action) {
      return res.status(400).json({ error: 'Action is required' });
    }
    const details = req.body?.details ? String(req.body.details) : null;
    const metadata = req.body?.metadata && typeof req.body.metadata === 'object' ? req.body.metadata : null;
    await insertAuditEvent({
      action,
      details,
      username: req.user?.username || null,
      userId: req.user?.id || null,
      ip: req.ip,
      userAgent: req.headers['user-agent'] || null,
      metadata
    });
    res.json({ success: true });
  } catch (error) {
    logger.error('Error inserting audit event', { error: error.message });
    res.status(500).json({ error: 'Failed to insert audit event' });
  }
});

app.get('/api/audit/events', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const limit = Number(req.query.limit || 200);
    const safeLimit = Number.isFinite(limit) ? Math.min(Math.max(limit, 1), 1000) : 200;
    const items = await listAuditEvents(safeLimit);
    res.json({ items });
  } catch (error) {
    logger.error('Error listing audit events', { error: error.message });
    res.status(500).json({ error: 'Failed to list audit events' });
  }
});

app.post('/api/events/budget-exceeded', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    emitEventWebhook('budget_exceeded', {
      user: req.user?.username || null,
      data: req.body || {}
    });
    res.json({ success: true });
  } catch (error) {
    logger.error('Budget event error', { error: error.message });
    res.status(500).json({ error: 'Failed to emit budget event' });
  }
});

app.post('/api/events/role-change', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    emitEventWebhook('role_changed', {
      user: req.user?.username || null,
      data: req.body || {}
    });
    res.json({ success: true });
  } catch (error) {
    logger.error('Role event error', { error: error.message });
    res.status(500).json({ error: 'Failed to emit role event' });
  }
});

// Security: Protected route to fetch payments from Conta Azul API
app.get('/api/payments', authenticateToken, authorizeRole('user'), async (req, res) => {
  try {
    const response = await withCache('contaazul:payments', Number(process.env.CACHE_TTL_PAYMENTS || 60), async () => {
      const url = `${CONTA_AZUL_API_BASE_URL.replace(/\/+$/, '')}/${CONTA_AZUL_PAYMENTS_PATH.replace(/^\/+/, '')}`;
      const result = await contaAzulRequest({
        method: 'GET',
        url,
        headers: {
          'Content-Type': 'application/json'
        }
      }, { route: '/api/payments', user: req.user?.username });
      return result.data;
    });

    logger.info('Payments fetched successfully', { user: req.user.username, count: response?.length || 0 });
    res.json(response);
  } catch (error) {
    logTimeout(error, { service: 'conta_azul', route: '/api/payments', timeout_ms: CONTA_AZUL_TIMEOUT_MS });
    logger.error('Error fetching payments', {
      error: error.message,
      user: req.user?.username,
      status: error.response?.status || null,
      data: error.response?.data || null
    });
    res.status(500).json({ error: 'Failed to fetch payments from Conta Azul API' });
  }
});

// Shared flow payments storage (local DB)
app.get('/api/flow-payments', authenticateToken, authorizeRole('user'), requireCompanyParam, enforceCompanyAccess, async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const company = normalizeCompany(req.query.company);
    const payments = await listFlowPayments(company);
    res.json({ payments });
  } catch (error) {
    logger.error('Error listing flow payments', { error: error.message });
    res.status(500).json({ error: 'Failed to list flow payments' });
  }
});

app.get('/api/flow-payments/stream', authenticateTokenFromQuery, authorizeRole('user'), requireCompanyParam, enforceCompanyAccess, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const company = normalizeCompany(req.query.company) || null;
  const subscriber = { res, company };
  flowSubscribers.add(subscriber);

  res.write(`event: flow_update\n`);
  res.write(`data: ${JSON.stringify({ type: 'connected', company })}\n\n`);

  const keepAlive = setInterval(() => {
    res.write(': ping\n\n');
  }, 25000);

  req.on('close', () => {
    clearInterval(keepAlive);
    flowSubscribers.delete(subscriber);
  });
});

app.post(
  '/api/flow-payments/import',
  authenticateToken,
  authorizeRole('user'),
  authorizePermission('import_payments'),
  enforceCompanyAccess,
  importLimiter,
  validateRequest([
    body('payments').optional().isArray(),
    body().custom(bodyValue => {
      if (Array.isArray(bodyValue)) return true;
      if (bodyValue && Array.isArray(bodyValue.payments)) return true;
      return false;
    }).withMessage('Payments array required'),
    body('company').optional().isString()
  ]),
  async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const items = Array.isArray(req.body) ? req.body : (req.body?.payments || []);
    const company = normalizeCompany(req.query.company || req.body?.company) || 'DMF';
    const dedup = new Map();
    for (const item of items) {
      const id = String(item.id || crypto.randomUUID());
      dedup.set(id, {
        id,
        company,
        fornecedor: item.fornecedor || 'N/A',
        data: item.data || null,
        descricao: item.descricao || '',
        valor: Number(item.valor) || 0,
        centro: item.centro || '',
        categoria: item.categoria || '',
        assinatura: item.assinatura || null,
        version: Number.isFinite(item.version) ? Number(item.version) : 0,
        updated_by: req.user?.username || null,
        created_at: item.created_at || new Date(),
        updated_at: new Date()
      });
    }
    const normalized = Array.from(dedup.values());
    await replaceFlowPayments(normalized, company);
    await recordAuditEvent(req, normalized.length ? 'FLOW_IMPORT' : 'FLOW_CLEAR', `Fluxo ${company} importado (${normalized.length} registros).`, {
      company,
      count: normalized.length
    });
    notifyFlowSubscribers(company, {
      type: 'flow_imported',
      company,
      count: normalized.length
    });
    res.json({ success: true, count: normalized.length });
  } catch (error) {
    logger.error('Error importing flow payments', { error: error.message });
    res.status(500).json({ error: 'Failed to import flow payments' });
  }
  }
);

app.post(
  '/api/flow-payments',
  authenticateToken,
  authorizeRole('user'),
  authorizePermission('add_payments'),
  enforceCompanyAccess,
  validateRequest([
    body('fornecedor').optional().isLength({ min: 1 }),
    body('valor').optional().isNumeric(),
    body('company').optional().isString()
  ]),
  async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const item = req.body || {};
    const company = normalizeCompany(req.query.company || item.company) || 'DMF';
    const payment = {
      id: String(item.id || crypto.randomUUID()),
      company,
      fornecedor: item.fornecedor || 'N/A',
      data: item.data || null,
      descricao: item.descricao || '',
      valor: Number(item.valor) || 0,
      centro: item.centro || '',
      categoria: item.categoria || '',
      assinatura: item.assinatura || null,
      version: Number.isFinite(item.version) ? Number(item.version) : 0,
      updated_by: req.user?.username || null,
      created_at: new Date(),
      updated_at: new Date()
    };
    let saved = null;
    if (Number.isFinite(item.version)) {
      const expected = Number(item.version);
      const existing = await getFlowPaymentById(payment.id, company);
      if (existing && Number(existing.version || 0) !== expected) {
        return respondConflict(req, res, {
          code: 'FLOW_VERSION_CONFLICT',
          message: `Conflito de versão para o pagamento ${payment.id}.`,
          payload: {
            current: existing,
            expectedVersion: expected,
            currentVersion: Number(existing.version || 0)
          },
          metadata: {
            company,
            paymentId: payment.id,
            expectedVersion: expected,
            currentVersion: Number(existing.version || 0)
          }
        });
      }
      if (existing) {
        // Avoid mutating created_at, keep ordering stable.
        const { created_at, ...updates } = payment;
        saved = await updateFlowPaymentWithVersion(payment.id, updates, expected, company);
        if (!saved) {
          const current = await getFlowPaymentById(payment.id, company);
          return respondConflict(req, res, {
            code: 'FLOW_VERSION_CONFLICT',
            message: `Conflito de versão para o pagamento ${payment.id}.`,
            payload: {
              current: current || null,
              expectedVersion: expected,
              currentVersion: Number(current?.version || 0)
            },
            metadata: {
              company,
              paymentId: payment.id,
              expectedVersion: expected,
              currentVersion: Number(current?.version || 0)
            }
          });
        }
      }
    }
    if (!saved) {
    await upsertFlowPayment(payment);
      saved = payment;
    }
    await recordAuditEvent(req, 'FLOW_UPSERT', `Pagamento ${payment.id} criado/atualizado em ${company}.`, {
      company,
      paymentId: payment.id
    });
    notifyFlowSubscribers(company, {
      type: 'payment_upserted',
      company,
      payment: saved
    });
    res.json({ success: true, payment: saved });
  } catch (error) {
    logger.error('Error creating flow payment', { error: error.message });
    res.status(500).json({ error: 'Failed to create flow payment' });
  }
  }
);

app.patch(
  '/api/flow-payments/:id/sign',
  authenticateToken,
  authorizeRole('user'),
  authorizePermission('sign_payments'),
  enforceCompanyAccess,
  validateRequest([
    param('id').notEmpty().withMessage('Payment id required')
  ]),
  async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const paymentId = req.params.id;
    const incoming = req.body?.assinatura && typeof req.body.assinatura === 'object' ? req.body.assinatura : {};
    // Server is the source of truth for who/when signed (auditability across devices).
    const assinatura = {
      ...incoming,
      usuarioNome: req.user?.username || req.user?.email || incoming?.usuarioNome || 'usuario',
      userId: req.user?.id || null,
      ip: req.ip,
      dataISO: new Date().toISOString()
    };
    const company = normalizeCompany(req.query.company || req.body?.company) || 'DMF';
    const updated = await signFlowPaymentIfUnsigned(paymentId, assinatura, company);
    if (!updated) {
      const existing = await getFlowPaymentById(paymentId, company);
      return respondConflict(req, res, {
        code: 'FLOW_SIGN_CONFLICT',
        message: `Tentativa de assinar pagamento ja assinado (${paymentId}).`,
        payload: { payment: existing || null },
        metadata: {
          company,
          paymentId,
          alreadySigned: !!existing?.assinatura
        }
      });
    }
    const payments = await listFlowPayments(company);
    const withChain = applyChainHashes(payments);
    await Promise.all(
      withChain
        .filter(p => p?.assinatura?.chain_hash)
        .map(p => updateFlowPayment(p.id, { assinatura: p.assinatura }, company))
    );
    const refreshed = withChain.find(p => String(p.id) === String(paymentId)) || updated;
    notifyFlowSubscribers(company, {
      type: 'payment_signed',
      paymentId,
      company,
      assinatura: refreshed?.assinatura || null
    });
    emitEventWebhook('payment_signed', {
      paymentId,
      user: req.user?.username || null,
      assinatura: refreshed?.assinatura || null
    });
    await recordAuditEvent(req, 'FLOW_SIGN', `Pagamento ${paymentId} assinado em ${company}.`, {
      company,
      paymentId
    });
    res.json({ success: true, payment: refreshed });
  } catch (error) {
    logger.error('Error signing flow payment', { error: error.message });
    res.status(500).json({ error: 'Failed to sign flow payment' });
  }
  }
);

// Archived flow snapshots
app.get('/api/flow-archives', authenticateToken, authorizeRole('user'), authorizePermission('view_archives'), requireCompanyParam, enforceCompanyAccess, async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const company = normalizeCompany(req.query.company);
    const archives = await listFlowArchives(company);
    const start = req.query.start ? new Date(String(req.query.start)) : null;
    const end = req.query.end ? new Date(String(req.query.end)) : null;
    let filtered = archives;
    if (start && !isNaN(start.getTime())) {
      filtered = filtered.filter(a => new Date(a.created_at).getTime() >= start.getTime());
    }
    if (end && !isNaN(end.getTime())) {
      filtered = filtered.filter(a => new Date(a.created_at).getTime() <= end.getTime());
    }
    res.json({ archives: filtered });
  } catch (error) {
    logger.error('Error listing flow archives', { error: error.message });
    res.status(500).json({ error: 'Failed to list flow archives' });
  }
});

app.post(
  '/api/flow-archives',
  authenticateToken,
  authorizeRole('admin'),
  authorizePermission('archive_flow'),
  enforceCompanyAccess,
  criticalLimiter,
  validateRequest([
    body('company').optional().isString()
  ]),
  async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const company = normalizeCompany(req.query.company || req.body?.company) || 'DMF';
    const payments = await listFlowPayments(company);
    if (!payments.length) {
      return res.status(400).json({ error: 'Nenhum pagamento para arquivar.' });
    }
    const unsignedCount = payments.filter(p => !p.assinatura).length;
    if (unsignedCount > 0) {
      return res.status(400).json({
        error: 'Existem pagamentos pendentes de assinatura.',
        pending: unsignedCount
      });
    }
    const now = new Date();
    const labelDate = now.toLocaleDateString('pt-BR');
    const displayName = (req.user?.name || req.user?.username || '').trim();
    const label = displayName
      ? `Fluxo ${company} (${labelDate}) - ${displayName}`
      : `Fluxo ${company} (${labelDate})`;
    const withChain = applyChainHashes(payments);
    await Promise.all(
      withChain
        .filter(p => p?.assinatura?.chain_hash)
        .map(p => updateFlowPayment(p.id, { assinatura: p.assinatura }, company))
    );
    const archive = await createFlowArchive({
      id: crypto.randomUUID(),
      label,
      company,
      payments: withChain,
      createdBy: req.user?.username || null,
      count: withChain.length
    });
    await recordAuditEvent(req, 'FLOW_ARCHIVE_CREATE', `Fluxo arquivado (${company}).`, {
      company,
      count: withChain.length,
      archiveId: archive?.id || null
    });
    await replaceFlowPayments([], company);
    emitEventWebhook('flow_archived', {
      archiveId: archive?.id,
      label: archive?.label,
      count: archive?.count,
      user: req.user?.username || null
    });
    res.json({ success: true, archive });
  } catch (error) {
    logger.error('Error creating flow archive', { error: error.message });
    res.status(500).json({ error: 'Failed to create flow archive' });
  }
});

app.delete(
  '/api/flow-archives/:id',
  authenticateToken,
  authorizeRole('admin'),
  authorizePermission('delete_archive'),
  enforceCompanyAccess,
  criticalLimiter,
  validateRequest([
    param('id').notEmpty().withMessage('Archive id required')
  ]),
  async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const archiveId = req.params.id;
    const deleted = await deleteFlowArchive(archiveId);
    await recordAuditEvent(req, 'FLOW_ARCHIVE_DELETE', `Fluxo arquivado removido (${archiveId}).`, {
      archiveId
    });
    res.json({ success: true, deleted: Number(deleted) || 0 });
  } catch (error) {
    logger.error('Error deleting flow archive', { error: error.message });
    res.status(500).json({ error: 'Failed to delete flow archive' });
  }
});

// Security: Protected route to sign a payment (requires gestor or admin)
app.post('/api/payments/:id/sign', authenticateToken, authorizeRole('gestor'), authorizePermission('sign_payments'), [
  param('id').notEmpty().withMessage('Payment ID required'),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Payment sign validation failed', { errors: errors.array(), user: req.user.username });
      return res.status(400).json({ errors: errors.array() });
    }

    const paymentId = req.params.id;

    const url = `${CONTA_AZUL_API_BASE_URL.replace(/\/+$/, '')}/${CONTA_AZUL_PAYMENTS_PATH.replace(/^\/+/, '')}/${paymentId}/sign`;
    const response = await contaAzulRequest({
      method: 'POST',
      url,
      data: {},
      headers: {
        'Content-Type': 'application/json'
      }
    }, { route: '/api/payments/:id/sign', paymentId, user: req.user?.username });

    logger.info('Payment signed successfully', {
      user: req.user.username,
      paymentId,
      status: response.status
    });
    await recordAuditEvent(req, 'PAYMENT_SIGN', `Pagamento assinado (${paymentId}).`, {
      paymentId
    });
    res.json({ message: 'Payment signed successfully', data: response.data });
  } catch (error) {
    logTimeout(error, { service: 'conta_azul', route: '/api/payments/:id/sign', timeout_ms: CONTA_AZUL_TIMEOUT_MS });
    logger.error('Error signing payment', {
      error: error.message,
      user: req.user?.username,
      paymentId: req.params.id,
      status: error.response?.status || null,
      data: error.response?.data || null
    });
    res.status(500).json({ error: 'Failed to sign payment' });
  }
});

// Security: Protected route to remove a payment flow (requires admin)
app.delete('/api/payments/:id', authenticateToken, authorizeRole('admin'), authorizePermission('delete_payments'), criticalLimiter, [
  param('id').notEmpty().withMessage('Payment ID required'),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Payment delete validation failed', { errors: errors.array(), user: req.user.username });
      return res.status(400).json({ errors: errors.array() });
    }

    const paymentId = req.params.id;

    const url = `${CONTA_AZUL_API_BASE_URL.replace(/\/+$/, '')}/${CONTA_AZUL_PAYMENTS_PATH.replace(/^\/+/, '')}/${paymentId}`;
    const response = await contaAzulRequest({
      method: 'DELETE',
      url,
      headers: {
        'Content-Type': 'application/json'
      }
    }, { route: '/api/payments/:id', paymentId, user: req.user?.username });

    logger.info('Payment flow removed successfully', {
      user: req.user.username,
      paymentId,
      status: response.status
    });
    await recordAuditEvent(req, 'PAYMENT_DELETE', `Pagamento removido (${paymentId}).`, {
      paymentId
    });
    res.json({ message: 'Payment flow removed successfully' });
  } catch (error) {
    logTimeout(error, { service: 'conta_azul', route: '/api/payments/:id', timeout_ms: CONTA_AZUL_TIMEOUT_MS });
    logger.error('Error removing payment flow', {
      error: error.message,
      user: req.user?.username,
      paymentId: req.params.id,
      status: error.response?.status || null,
      data: error.response?.data || null
    });
    res.status(500).json({ error: 'Failed to remove payment flow' });
  }
});

// Security: Generate signature hash (requires login)
app.post('/api/signatures/hmac', authenticateToken, authorizeRole('user'), async (req, res) => {
  try {
    if (!SIGNATURE_SECRET) {
      return res.status(500).json({ error: 'Signature secret not configured' });
    }

    const { paymentId, userName, dataISO, valor, centro } = req.body || {};
    if (!paymentId || !userName || !dataISO) {
      return res.status(400).json({ error: 'Missing signature fields' });
    }

    const payload = `${paymentId}|${userName}|${dataISO}|${valor || ''}|${centro || ''}`;
    const hash = crypto.createHmac('sha256', SIGNATURE_SECRET).update(payload).digest('hex');
    res.json({ hash });
  } catch (error) {
    logger.error('Signature hash error', { error: error.message });
    res.status(500).json({ error: 'Failed to generate signature hash' });
  }
});

// Security: Verify signature hash (requires login)
app.post('/api/signatures/verify', authenticateToken, authorizeRole('user'), async (req, res) => {
  try {
    if (!SIGNATURE_SECRET) {
      return res.status(500).json({ error: 'Signature secret not configured' });
    }

    const { paymentId, userName, dataISO, valor, centro, hash } = req.body || {};
    if (!paymentId || !userName || !dataISO || !hash) {
      return res.status(400).json({ error: 'Missing signature fields' });
    }

    const payload = `${paymentId}|${userName}|${dataISO}|${valor || ''}|${centro || ''}`;
    const expected = crypto.createHmac('sha256', SIGNATURE_SECRET).update(payload).digest('hex');
    const valid = expected === hash;
    res.json({ valid });
  } catch (error) {
    logger.error('Signature verify error', { error: error.message });
    res.status(500).json({ error: 'Failed to verify signature hash' });
  }
});

// Public signature verification (no auth)
app.get('/api/public/signatures/:hash', async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const hash = String(req.params.hash || '').trim();
    if (!hash) {
      return res.status(400).json({ error: 'Signature hash required' });
    }

    const checkSet = (payments, sourceLabel, sourceType) => {
      const computed = applyChainHashes(payments || []);
      const found = computed.find(p => p?.assinatura?.hash === hash);
      if (!found) return null;
      const original = (payments || []).find(p => String(p.id) === String(found.id));
      const storedChain = original?.assinatura?.chain_hash || null;
      const chainValid = storedChain ? storedChain === found.assinatura.chain_hash : true;
      return {
        valid: true,
        nome: found.assinatura?.usuarioNome || null,
        dataISO: found.assinatura?.dataISO || null,
        hash,
        chainValid,
        source: { type: sourceType, label: sourceLabel }
      };
    };

    const current = await listFlowPayments();
    let result = checkSet(current, 'Fluxo Atual', 'current');
    if (!result) {
      const archives = await listFlowArchives();
      for (const archive of archives) {
        result = checkSet(archive?.payments || [], archive?.label || 'Fluxo Arquivado', 'archive');
        if (result) break;
      }
    }

    if (!result) {
      return res.status(404).json({ valid: false, error: 'Assinatura invalida' });
    }
    res.json(result);
  } catch (error) {
    logger.error('Error verifying public signature', { error: error.message });
    res.status(500).json({ error: 'Failed to verify signature' });
  }
});

// Cobli health check
app.get('/api/cobli/health', (req, res) => {
  res.json({
    configured: !!COBLI_API_BASE_URL && !!COBLI_API_TOKEN,
    base_url: COBLI_API_BASE_URL || null
  });
});

// Security: Protected Cobli generic proxy
app.all('/api/cobli/proxy', authenticateToken, authorizeRole('user'), [
  query('path').notEmpty().withMessage('Path parameter required'),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Cobli proxy validation failed', { errors: errors.array(), user: req.user.username });
      return res.status(400).json({ errors: errors.array() });
    }

    const path = req.query.path;
    const { path: _, ...params } = req.query;

    const response = await cobliRequest(req.method, path, {
      params,
      data: req.body
    });

    logger.info('Cobli proxy request successful', {
      user: req.user.username,
      method: req.method,
      path,
      status: response.status
    });

    res.status(response.status).json(response.data);
  } catch (error) {
    logTimeout(error, { service: 'cobli', route: '/api/cobli/proxy', timeout_ms: COBLI_TIMEOUT_MS });
    logger.error('Cobli proxy error', {
      error: error.message,
      user: req.user?.username,
      method: req.method,
      path: req.query.path
    });
    res.status(500).json({ error: 'Failed to call Cobli API' });
  }
});

// Security: Protected route to fetch payments from Cobli API
app.get('/api/cobli/payments', authenticateToken, authorizeRole('user'), async (req, res) => {
  try {
    const response = await withCache('cobli:payments', Number(process.env.CACHE_TTL_COBLI_PAYMENTS || 60), async () => {
      const result = await cobliRequest('GET', '/payments');
      return result.data;
    });
    logger.info('Cobli payments fetched successfully', { user: req.user.username, count: response?.length || 0 });
    res.json(response);
  } catch (error) {
    logTimeout(error, { service: 'cobli', route: '/api/cobli/payments', timeout_ms: COBLI_TIMEOUT_MS });
    logger.error('Error fetching payments from Cobli API', { error: error.message, user: req.user?.username });
    res.status(500).json({ error: 'Failed to fetch payments from Cobli API' });
  }
});

// Route to fetch vehicle locations from Cobli API
app.get('/api/cobli/vehicle-locations', authenticateToken, authorizeRole('user'), async (req, res) => {
  try {
    const response = await withCache('cobli:vehicle_locations', Number(process.env.CACHE_TTL_COBLI_LOCATIONS || 30), async () => {
      const result = await cobliRequest('GET', '/vehicles/locations');
      return result.data;
    });
    res.json(response);
  } catch (error) {
    logTimeout(error, { service: 'cobli', route: '/api/cobli/vehicle-locations', timeout_ms: COBLI_TIMEOUT_MS });
    console.error('Error fetching vehicle locations from Cobli API:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to fetch vehicle locations from Cobli API' });
  }
});

// Cobli webhook
app.post('/webhooks/cobli', async (req, res) => {
  const verified = verifyCobliSignature(req);

  if (!verified) {
    return res.status(401).json({ error: 'Invalid webhook signature' });
  }

  try {
    await insertWebhook('cobli', req.body, req.headers);
    console.log('Cobli webhook received:', req.body);
    res.status(200).json({ ok: true });
  } catch (error) {
    logger.error('Cobli webhook storage failed', { error: error.message });
    res.status(500).json({ error: 'Failed to store webhook payload' });
  }
});

// Conta Azul webhook (signature validation optional)
app.post('/webhooks/contaazul', async (req, res) => {
  const secret = process.env.CONTA_AZUL_WEBHOOK_SECRET;
  const header = process.env.CONTA_AZUL_WEBHOOK_SIGNATURE_HEADER || 'X-ContaAzul-Signature';

  if (secret) {
    const signature = req.get(header);
    if (!signature || !req.rawBody) {
      return res.status(401).json({ error: 'Invalid webhook signature' });
    }

    const expected = crypto
      .createHmac('sha256', secret)
      .update(req.rawBody)
      .digest('hex');

    const normalizedSignature = signature.startsWith('sha256=')
      ? signature.slice('sha256='.length)
      : signature;

    if (normalizedSignature !== expected) {
      return res.status(401).json({ error: 'Invalid webhook signature' });
    }
  }

  try {
    await insertWebhook('contaazul', req.body, req.headers);
    res.status(200).json({ ok: true });
  } catch (error) {
    logger.error('Conta Azul webhook storage failed', { error: error.message });
    res.status(500).json({ error: 'Failed to store webhook payload' });
  }
});

// Route to manually refresh token (for testing)
app.post('/api/auth/refresh', async (req, res) => {
  try {
    await refreshAccessToken();
    res.json({ message: 'Token refreshed successfully', token_expiry: tokenExpiry });
  } catch (error) {
    console.error('Error refreshing token:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to refresh token' });
  }
});

// Route to check authentication status
app.get('/api/auth/status', (req, res) => {
  res.json({
    authenticated: !!accessToken,
    token_expiry: tokenExpiry,
    deprecated: true,
    note: 'Use /api/auth/service-status or /api/auth/user-status'
  });
});

// Route to check service authentication status (Conta Azul token)
app.get('/api/auth/service-status', (req, res) => {
  res.json({
    authenticated: !!accessToken,
    token_expiry: tokenExpiry
  });
});

// Route to check user authentication status (JWT)
app.get('/api/auth/user-status', authenticateToken, async (req, res) => {
  const permissions = await loadRolePermissions(req.user?.role);
  res.json({
    authenticated: true,
    user: {
      ...sanitizeUserForResponse(req.user),
      permissions
    }
  });
});

// Cron: automated backup (App Engine)
app.post('/tasks/backup', async (req, res) => {
  const isCron = req.get('X-Appengine-Cron') === 'true';
  const secret = req.get('X-Cron-Secret');
  if (!isCron && (!CRON_SECRET || secret !== CRON_SECRET)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  try {
    if (!isDbReady()) {
      logger.error('ALERT_DB_DOWN', { route: '/tasks/backup' });
      return res.status(503).json({ error: 'Database not ready' });
    }
    const users = await listUsers();
    const payments = await listFlowPayments();
    const archives = await listFlowArchives();
    const payload = {
      created_at: new Date().toISOString(),
      users,
      payments,
      archives
    };
    await insertBackupSnapshot({ createdBy: 'cron', payload });
    logger.info('Backup snapshot created', { count_users: users.length, count_payments: payments.length, count_archives: archives.length });
    res.json({ success: true });
  } catch (error) {
    logger.error('Backup cron failed', { error: error.message });
    res.status(500).json({ error: 'Backup cron failed' });
  }
});

// Health check
app.get('/api/health', async (req, res) => {
  const dbReady = isDbReady();
  let roleCount = null;
  if (dbReady) {
    try {
      const roles = await listRoles();
      roleCount = roles.length;
    } catch (_) {
      roleCount = null;
    }
  }
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    boot: {
      ready: bootState.ready,
      started_at: bootState.startedAt,
      fatal_error: bootState.fatalError && shouldExposeStartupError() ? bootState.fatalError : null
    },
    db_ready: dbReady,
    db: describeDatabaseUrl(process.env.DATABASE_URL),
    permissions_enforced: PERMISSIONS_ENFORCED,
    company_access_enforced: ENFORCE_COMPANY_ACCESS,
    secret_manager_enabled: process.env.SECRET_MANAGER_ENABLED === 'true',
    secret_manager_project: process.env.GCP_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT || null,
    roles: roleCount,
    runtime: {
      sse_subscribers: flowSubscribers.size,
      conflicts_total: runtimeStats.conflictsTotal,
      last_conflict_at: runtimeStats.lastConflictAt
    },
    services: {
      conta_azul_configured: !!CLIENT_ID && !!CLIENT_SECRET && !!TOKEN_URL,
      cobli_configured: !!COBLI_API_BASE_URL && !!COBLI_API_TOKEN
    },
    tokens: {
      conta_azul_authenticated: !!accessToken,
      conta_azul_expires_at: tokenExpiry ? new Date(tokenExpiry).toISOString() : null
    }
  });
});

app.get('/api/companies', authenticateToken, authorizeRole('user'), (req, res) => {
  // Used by the UI to list/select companies safely.
  res.json({ companies: DEFAULT_COMPANIES_UNIQUE });
});

app.get('/api/reports/monthly', authenticateToken, authorizeRole('user'), async (req, res) => {
  const monthKey = String(req.query.month || req.query.monthKey || '').trim();
  if (!/^\d{4}-\d{2}$/.test(monthKey)) {
    return res.status(400).json({ error: 'Invalid month. Use YYYY-MM.' });
  }

  try {
    // Always cap to the allow-list, even for admins.
    let companies = DEFAULT_COMPANIES_UNIQUE;
    if (ENFORCE_COMPANY_ACCESS && isDbReady() && normalizeRole(req.user?.role) !== 'admin') {
      const resolved = await resolveCompanyAccess(req.user?.id, req.user?.role);
      if (Array.isArray(resolved) && resolved.length) {
        companies = resolved;
      } else if (!ALLOW_ALL_COMPANIES_WHEN_UNSET) {
        return res.status(403).json({ error: 'Company access not configured' });
      }
    }

    companies = (companies || []).map(normalizeCompany).filter((c) => c && isAllowedCompany(c));
    if (!companies.length) {
      return res.status(403).json({ error: 'No companies allowed' });
    }

    const report = await getMonthlyReport({ monthKey, companies });
    const budgetRows = await listBudgetLimits(monthKey, companies);
    const budgets = (budgetRows || []).reduce((acc, row) => {
      const company = normalizeCompany(row.company);
      if (!company) return acc;
      acc[company] = Number(row.limit_value || 0) || 0;
      return acc;
    }, {});

    // Ensure stable keys for the known companies (even if 0).
    DEFAULT_COMPANIES_UNIQUE.forEach((c) => {
      if (!Object.prototype.hasOwnProperty.call(report.totals_by_company || {}, c)) {
        report.totals_by_company[c] = 0;
      }
      if (!Object.prototype.hasOwnProperty.call(budgets, c)) {
        budgets[c] = 0;
      }
    });

    return res.json({
      month: monthKey,
      companies,
      report,
      budgets,
    });
  } catch (error) {
    logger.error('Monthly report failed', { error: error.message });
    return res.status(500).json({ error: 'Failed to generate report' });
  }
});

app.put('/api/budgets', authenticateToken, authorizeRole('admin'), authorizePermission('admin_access'), criticalLimiter, async (req, res) => {
  const monthKey = String(req.query.month || req.body?.month || '').trim();
  if (!/^\d{4}-\d{2}$/.test(monthKey)) {
    return res.status(400).json({ error: 'Invalid month. Use YYYY-MM.' });
  }
  const budgets = req.body?.budgets && typeof req.body.budgets === 'object' ? req.body.budgets : null;
  if (!budgets) {
    return res.status(400).json({ error: 'budgets object required' });
  }

  // Only allow writing the known allow-list companies.
  const filtered = {};
  for (const [k, v] of Object.entries(budgets)) {
    const company = normalizeCompany(k);
    if (!company || !isAllowedCompany(company)) continue;
    const n = Number(v || 0);
    if (!Number.isFinite(n) || n < 0) continue;
    filtered[company] = n;
  }

  try {
    const count = await upsertBudgetLimits(monthKey, filtered, req.user?.username || null);
    await recordAuditEvent(req, 'BUDGETS_UPDATED', `Orcamentos atualizados para ${monthKey}.`, {
      month: monthKey,
      companies: Object.keys(filtered),
      count
    });
    return res.json({ status: 'ok', updated: count });
  } catch (error) {
    logger.error('Failed to save budgets', { error: error.message });
    return res.status(500).json({ error: 'Failed to save budgets' });
  }
});

// Admin: list roles
app.get('/api/roles', authenticateToken, authorizeRole('admin'), authorizePermission('roles_manage'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const roles = await listRoles();
    res.json({ roles });
  } catch (error) {
    logger.error('Failed to list roles', { error: error.message });
    res.status(500).json({ error: 'Failed to list roles' });
  }
});

// Admin: manage user company access
app.get('/api/users/:id/companies', authenticateToken, authorizeRole('admin'), authorizePermission('user_manage'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const userId = Number(req.params.id);
    const companies = await listUserCompanies(userId);
    res.json({ companies });
  } catch (error) {
    logger.error('Failed to list user companies', { error: error.message });
    res.status(500).json({ error: 'Failed to list user companies' });
  }
});

app.put(
  '/api/users/:id/companies',
  authenticateToken,
  authorizeRole('admin'),
  authorizePermission('user_manage'),
  validateRequest([
    param('id').isInt().withMessage('Valid user ID required'),
    body('companies').isArray().withMessage('Companies array required')
  ]),
  async (req, res) => {
    try {
      if (!isDbReady()) {
        return res.status(503).json({ error: 'Database not ready' });
      }
      const userId = Number(req.params.id);
      const companies = (req.body.companies || []).map(c => normalizeCompany(c)).filter(Boolean);
      await replaceUserCompanies(userId, Array.from(new Set(companies)));
      await recordAuditEvent(req, 'USER_COMPANIES_UPDATED', `Empresas atualizadas para usuário ${userId}.`, {
        userId,
        companies
      });
      res.json({ success: true });
    } catch (error) {
      logger.error('Failed to update user companies', { error: error.message });
      res.status(500).json({ error: 'Failed to update user companies' });
    }
  }
);

app.get('/api/centers/companies', authenticateToken, authorizeRole('user'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const items = await listCenterCompanies();
    res.json({
      items: items.map(item => ({
        center_key: item.center_key,
        center_label: item.center_label,
        company: item.company
      }))
    });
  } catch (error) {
    logger.error('Error listing center companies', { error: error.message });
    res.status(500).json({ error: 'Failed to list center companies' });
  }
});

app.put(
  '/api/centers/companies',
  authenticateToken,
  authorizeRole('admin'),
  authorizePermission('user_manage'),
  validateRequest([
    body('center').notEmpty().withMessage('Center name required'),
    body('company').notEmpty().withMessage('Company required')
  ]),
  async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const centerLabel = String(req.body.center || '').trim();
    const centerKey = centerLabel.toLowerCase();
    const company = String(req.body.company || '').trim();
    const saved = await upsertCenterCompany(centerKey, centerLabel, company);
    await recordAuditEvent(req, 'CENTER_COMPANY_UPDATE', `Centro ${centerLabel} → ${company}`, {
      center: centerLabel,
      company
    });
    res.json({ success: true, item: saved });
  } catch (error) {
    logger.error('Error updating center company', { error: error.message });
    res.status(500).json({ error: 'Failed to update center company' });
  }
});

app.post(
  '/api/centers/companies/bulk',
  authenticateToken,
  authorizeRole('admin'),
  authorizePermission('user_manage'),
  validateRequest([
    body('items').isArray().withMessage('Items array required')
  ]),
  async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const items = Array.isArray(req.body.items) ? req.body.items : [];
    const count = await bulkUpsertCenterCompanies(items);
    await recordAuditEvent(req, 'CENTER_COMPANY_BULK_UPDATE', `Centros atualizados em lote (${count}).`, {
      count
    });
    res.json({ success: true, count });
  } catch (error) {
    logger.error('Error bulk updating center companies', { error: error.message });
    res.status(500).json({ error: 'Failed to update center companies' });
  }
});

// Admin: upsert role
app.put(
  '/api/roles/:name',
  authenticateToken,
  authorizeRole('admin'),
  authorizePermission('roles_manage'),
  validateRequest([
    param('name').notEmpty().withMessage('Role name required'),
    body('permissions').isArray().withMessage('Permissions array required')
  ]),
  async (req, res) => {
    try {
      if (!isDbReady()) {
        return res.status(503).json({ error: 'Database not ready' });
      }
      const name = normalizeRole(req.params.name);
      const permissions = Array.isArray(req.body.permissions)
        ? req.body.permissions.map(p => String(p).trim()).filter(Boolean)
        : [];
      const updated = await upsertRole(name, permissions);
      roleCache.loadedAt = 0;
      await recordAuditEvent(req, 'ROLE_UPDATED', `Cargo ${name} atualizado.`, {
        role: name,
        permissions
      });
      res.json({ role: updated });
    } catch (error) {
      logger.error('Failed to upsert role', { error: error.message });
      res.status(500).json({ error: 'Failed to update role' });
    }
  }
);

// Admin: delete role
app.delete(
  '/api/roles/:name',
  authenticateToken,
  authorizeRole('admin'),
  authorizePermission('roles_manage'),
  criticalLimiter,
  validateRequest([
    param('name').notEmpty().withMessage('Role name required')
  ]),
  async (req, res) => {
    try {
      if (!isDbReady()) {
        return res.status(503).json({ error: 'Database not ready' });
      }
      const name = normalizeRole(req.params.name);
      if (name === 'admin') {
        return res.status(400).json({ error: 'Cannot delete admin role' });
      }
      const deleted = await deleteRoleByName(name);
      roleCache.loadedAt = 0;
      await recordAuditEvent(req, 'ROLE_DELETED', `Cargo ${name} removido.`, { role: name });
      res.json({ deleted: Number(deleted) || 0 });
    } catch (error) {
      logger.error('Failed to delete role', { error: error.message });
      res.status(500).json({ error: 'Failed to delete role' });
    }
  }
);

// Admin: revoke all sessions for a user
app.post('/api/auth/revoke/:id', authenticateToken, authorizeRole('admin'), authorizePermission('revoke_sessions'), criticalLimiter, [
  param('id').isInt().withMessage('Valid user ID required'),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    const userId = Number(req.params.id);
    await setUserSessionRevokedAfter(userId, new Date());
    emitEventWebhook('user_sessions_revoked', { userId, admin: req.user?.username || null });
    await recordAuditEvent(req, 'SESSIONS_REVOKED', `Sessões revogadas para usuário ${userId}.`, {
      userId
    });
    res.json({ success: true });
  } catch (error) {
    logger.error('Failed to revoke sessions', { error: error.message });
    res.status(500).json({ success: false, error: 'Failed to revoke sessions' });
  }
});

// Self: revoke current sessions (logout everywhere)
app.post('/api/auth/revoke-self', authenticateToken, authorizeRole('admin'), authorizePermission('revoke_sessions'), criticalLimiter, async (req, res) => {
  try {
    await setUserSessionRevokedAfter(req.user?.id, new Date());
    await recordAuditEvent(req, 'SESSIONS_REVOKED_SELF', 'Sessões revogadas pelo próprio usuário.', {
      userId: req.user?.id || null
    });
    res.json({ success: true });
  } catch (error) {
    logger.error('Failed to revoke own sessions', { error: error.message });
    res.status(500).json({ success: false, error: 'Failed to revoke sessions' });
  }
});

// Admin: list users
app.get('/api/users', authenticateToken, authorizeRole('admin'), authorizePermission('user_manage'), async (req, res) => {
  try {
    let data = users.map(sanitizeUserForResponse);
    if (isDbReady()) {
      const dbUsers = await listUsers();
      data = dbUsers.map(sanitizeUserForResponse);
    }
    res.json({ success: true, users: data });
  } catch (error) {
    logger.error('Failed to list users', { error: error.message });
    res.status(500).json({ success: false, error: 'Failed to list users' });
  }
});

// Admin: update user
app.put('/api/users/:id', authenticateToken, authorizeRole('admin'), authorizePermission('user_manage'), [
  param('id').isInt().withMessage('Valid user ID required'),
  body('username').optional().isLength({ min: 3, max: 50 }).trim().escape(),
  body('email').optional().isEmail().normalizeEmail(),
  body('role').optional().custom(isAllowedRole),
  body('name').optional().isLength({ min: 2, max: 100 }).trim().escape(),
  body('password').optional().isLength({ min: 8 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const userId = Number(req.params.id);
    if (req.user?.id === userId && req.body.role) {
      return res.status(400).json({ success: false, error: 'Cannot update own role via this endpoint' });
    }

    let user = users.find(u => Number(u.id) === userId);
    if (!user && isDbReady()) {
      user = await getUserById(userId);
    }
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    const oldRole = user.role;

    const updates = {};
    if (req.body.username) updates.username = String(req.body.username).trim();
    if (req.body.email) updates.email = String(req.body.email).trim().toLowerCase();
    if (req.body.role) updates.role = req.body.role;
    if (req.body.name) updates.name = req.body.name;
    if (req.body.password) {
      updates.password_hash = await bcrypt.hash(req.body.password, 12);
    }

    if ((updates.username || updates.email) && isDbReady()) {
      const dupe = await findUserByUsernameOrEmailExcludingId(
        updates.username || user.username,
        updates.email || user.email,
        userId
      );
      if (dupe) {
        return res.status(409).json({ success: false, error: 'User already exists' });
      }
    }

    if (isDbReady()) {
      user = await updateUserById(userId, updates);
    } else {
      Object.assign(user, updates);
    }

    if (updates.role && oldRole !== user.role) {
      emitEventWebhook('user_role_changed', {
        userId,
        username: user.username,
        oldRole,
        newRole: user.role,
        admin: req.user?.username || null
      });
    }
    if (req.body.password) {
      await recordAuditEvent(req, 'PASSWORD_RESET_ADMIN', `Senha redefinida para o usuário ${user.username}.`, {
        targetUserId: user.id,
        targetUsername: user.username
      });
    }

    await recordAuditEvent(req, 'USER_UPDATED', `Usuário ${user.username} atualizado.`, {
      targetUserId: user.id,
      targetUsername: user.username
    });
    res.json({ success: true, user: sanitizeUserForResponse(user) });
  } catch (error) {
    logger.error('Failed to update user', { error: error.message });
    res.status(500).json({ success: false, error: 'Failed to update user' });
  }
});

// Admin: delete user
app.delete('/api/users/:id', authenticateToken, authorizeRole('admin'), authorizePermission('user_manage'), criticalLimiter, [
  param('id').isInt().withMessage('Valid user ID required'),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const userId = Number(req.params.id);
    if (req.user?.id === userId) {
      return res.status(400).json({ success: false, error: 'Cannot delete your own account' });
    }

    let user = users.find(u => Number(u.id) === userId);
    if (!user && isDbReady()) {
      user = await getUserById(userId);
    }
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    if (isDbReady()) {
      await deleteUserById(userId);
    }
    const index = users.findIndex(u => Number(u.id) === userId);
    if (index >= 0) {
      users.splice(index, 1);
    }

    emitEventWebhook('user_deleted', {
      userId,
      username: user.username,
      admin: req.user?.username || null
    });

    await recordAuditEvent(req, 'USER_DELETED', `Usuário ${user.username} removido.`, {
      targetUserId: userId,
      targetUsername: user.username
    });
    res.json({ success: true });
  } catch (error) {
    logger.error('Failed to delete user', { error: error.message });
    res.status(500).json({ success: false, error: 'Failed to delete user' });
  }
});

// Admin: backup (users + flow + archives)
app.get('/api/backup', authenticateToken, authorizeRole('admin'), authorizePermission('backup_restore'), criticalLimiter, async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const users = await listUsers();
    const payments = await listFlowPayments();
    const archives = await listFlowArchives();
    await insertBackupSnapshot({
      createdBy: req.user?.username || null,
      payload: {
        created_at: new Date().toISOString(),
        users,
        payments,
        archives
      }
    });
    await recordAuditEvent(req, 'BACKUP_CREATED', 'Backup gerado com sucesso.', {
      users: users.length,
      payments: payments.length,
      archives: archives.length
    });
    res.json({
      created_at: new Date().toISOString(),
      users,
      payments,
      archives
    });
  } catch (error) {
    logger.error('Backup failed', { error: error.message });
    res.status(500).json({ error: 'Failed to generate backup' });
  }
});

// Admin: list backup snapshots
app.get('/api/backup/history', authenticateToken, authorizeRole('admin'), authorizePermission('backup_restore'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const limit = Number(req.query.limit || 20);
    const safeLimit = Number.isFinite(limit) ? Math.min(Math.max(limit, 1), 100) : 20;
    const items = await listBackupSnapshots(safeLimit);
    res.json({ items });
  } catch (error) {
    logger.error('Failed to list backup snapshots', { error: error.message });
    res.status(500).json({ error: 'Failed to list backup snapshots' });
  }
});

// Admin: restore (users + flow + archives)
app.post(
  '/api/restore',
  authenticateToken,
  authorizeRole('admin'),
  authorizePermission('backup_restore'),
  criticalLimiter,
  validateRequest([
    body('users').optional().isArray(),
    body('payments').optional().isArray(),
    body('archives').optional().isArray()
  ]),
  async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const payload = req.body || {};
    const users = Array.isArray(payload.users) ? payload.users : [];
    const payments = Array.isArray(payload.payments) ? payload.payments : [];
    const archives = Array.isArray(payload.archives) ? payload.archives : [];

    await replaceUsers(users.map(u => ({
      id: u.id,
      username: u.username,
      email: u.email,
      password_hash: u.password_hash,
      role: u.role,
      name: u.name || null,
      created_at: u.created_at || new Date(),
      last_login: u.last_login || null
    })));

    await replaceFlowPayments(payments.map(p => ({
      id: String(p.id),
      company: normalizeCompany(p.company) || 'DMF',
      fornecedor: p.fornecedor || 'N/A',
      data: p.data || null,
      descricao: p.descricao || '',
      valor: Number(p.valor) || 0,
      centro: p.centro || '',
      categoria: p.categoria || '',
      assinatura: p.assinatura || null,
      created_at: p.created_at || new Date(),
      updated_at: p.updated_at || new Date()
    })));

    await replaceFlowArchives(archives.map(a => ({
      id: String(a.id),
      label: a.label,
      company: normalizeCompany(a.company) || null,
      payments: a.payments || [],
      created_by: a.created_by || null,
      count: Number(a.count) || 0,
      created_at: a.created_at || new Date()
    })));

    emitEventWebhook('backup_restored', {
      user: req.user?.username || null,
      users: users.length,
      payments: payments.length,
      archives: archives.length
    });

    await recordAuditEvent(req, 'BACKUP_RESTORED', 'Backup restaurado.', {
      users: users.length,
      payments: payments.length,
      archives: archives.length
    });
    res.json({ success: true });
  } catch (error) {
    logger.error('Restore failed', { error: error.message });
    res.status(500).json({ error: 'Failed to restore backup' });
  }
  }
);

// CSRF error handler
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  return next(err);
});

let dbInitLoopRunning = false;

async function initializeDatabaseAndRuntime() {
  if (dbInitLoopRunning || isDbReady()) return;
  dbInitLoopRunning = true;
  const retryMs = Number(process.env.DB_STARTUP_RETRY_MS || 15000);
  while (!isDbReady()) {
    try {
      await initDb();
      logger.info('Database connected');
      const schema = await validateDbSchema();
      if (!schema.ok) {
        logger.error('ALERT_DB_SCHEMA_INVALID', { missing: schema.missing });
        if (DB_SCHEMA_STRICT) {
          throw new Error(`Database schema validation failed: ${schema.missing.join(', ')}`);
        }
      } else {
        logger.info('Database schema validated');
      }
      await loadTokensFromDb();
      logger.info('Runtime initialized');
      break;
    } catch (error) {
      logger.error('Database initialization failed, retrying', {
        error: error.message,
        retry_ms: retryMs
      });
      await new Promise(resolve => setTimeout(resolve, retryMs));
    }
  }
  dbInitLoopRunning = false;
}

// Start server
let httpServerStarted = false;

function startHttpServer() {
  if (httpServerStarted) return;
  httpServerStarted = true;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Conta Azul API integration ready');
  });
}

async function startServer() {
  startHttpServer();
  try {
    await loadSecretsFromSecretManager();
    applyRuntimeConfigFromEnv();

    if (process.env.NODE_ENV === 'production') {
      if (!JWT_SECRET) {
        throw new Error('JWT_SECRET is required in production');
      }
      if (!SIGNATURE_SECRET) {
        throw new Error('SIGNATURE_SECRET is required in production');
      }
      if (!process.env.DATABASE_URL) {
        throw new Error('DATABASE_URL is required in production');
      }
    }

    bootState.ready = true;
    initializeDatabaseAndRuntime().catch(error => {
      logger.error('Unexpected DB init loop failure', { error: error.message });
    });
  } catch (error) {
    bootState.ready = false;
    bootState.fatalError = error && error.message ? error.message : String(error);
    logger.error('Startup failed (server will keep running for diagnostics)', { error: bootState.fatalError });
  }
}

startServer().catch(error => {
  bootState.ready = false;
  bootState.fatalError = error && error.message ? error.message : String(error);
  logger.error('Unexpected startup failure', { error: bootState.fatalError });
});
