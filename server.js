require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
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
  updateFlowPayment,
  listFlowArchives,
  createFlowArchive,
  deleteFlowArchive,
  replaceFlowArchives,
  insertLoginAudit,
  listLoginAudits,
  getUserSession,
  setUserSessionRevokedAfter,
  insertWebhook
} = require('./db');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3001;
const EXTERNAL_API_TIMEOUT_MS = Number(process.env.EXTERNAL_API_TIMEOUT_MS || 10000);
const CONTA_AZUL_TIMEOUT_MS = Number(process.env.CONTA_AZUL_TIMEOUT_MS || EXTERNAL_API_TIMEOUT_MS);
const COBLI_TIMEOUT_MS = Number(process.env.COBLI_TIMEOUT_MS || EXTERNAL_API_TIMEOUT_MS);

const contaAzulClient = axios.create({ timeout: CONTA_AZUL_TIMEOUT_MS });
const cobliClient = axios.create({ timeout: COBLI_TIMEOUT_MS });

// Security: Configure Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'dmf-system' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production' || process.env.LOG_TO_CONSOLE === 'true') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

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
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
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

// Middleware
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// Serve static files
app.use(express.static(__dirname));

// Token storage (persisted in database)
let accessToken = null;
let refreshToken = null;
let tokenExpiry = null; // Will be set based on JWT expiry
const users = []; // In-memory fallback for transition
const JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV === 'production' ? null : 'dev-insecure-jwt-secret');

// OAuth2 Configuration
const CLIENT_ID = process.env.CONTA_AZUL_CLIENT_ID;
const CLIENT_SECRET = process.env.CONTA_AZUL_CLIENT_SECRET;
const TOKEN_URL = process.env.CONTA_AZUL_TOKEN_URL;
const CONTA_AZUL_API_BASE_URL = process.env.CONTA_AZUL_API_BASE_URL || 'https://api.contaazul.com';
const CONTA_AZUL_PAYMENTS_PATH = process.env.CONTA_AZUL_PAYMENTS_PATH || '/v2/payments';
const SIGNATURE_SECRET = process.env.SIGNATURE_SECRET || (process.env.NODE_ENV === 'production' ? null : 'dev-insecure-signature-secret');

// Cobli Configuration
const COBLI_API_BASE_URL = process.env.COBLI_API_BASE_URL;
const COBLI_API_TOKEN = process.env.COBLI_API_TOKEN;
const COBLI_AUTH_HEADER = process.env.COBLI_AUTH_HEADER || 'Authorization';
const COBLI_AUTH_SCHEME = process.env.COBLI_AUTH_SCHEME || 'Bearer';
const COBLI_WEBHOOK_SECRET = process.env.COBLI_WEBHOOK_SECRET;
const COBLI_WEBHOOK_SIGNATURE_HEADER = process.env.COBLI_WEBHOOK_SIGNATURE_HEADER;
const EVENT_WEBHOOK_URL = process.env.EVENT_WEBHOOK_URL || '';
const EVENT_WEBHOOK_SECRET = process.env.EVENT_WEBHOOK_SECRET || '';

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
  if (!accessToken || !tokenExpiry) {
    await loadTokensFromDb();
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

// Security: Authentication middleware
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    logger.warn('Access attempt without token', { ip: req.ip, path: req.path });
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    if (isDbReady()) {
      const session = await getUserSession(user.id);
      if (session?.revoked_after) {
        const iatMs = (user.iat || 0) * 1000;
        if (iatMs && iatMs < new Date(session.revoked_after).getTime()) {
          return res.status(403).json({ error: 'Session revoked' });
        }
      }
      const dbUser = await getUserById(user.id);
      if (!dbUser) {
        return res.status(403).json({ error: 'User not found' });
      }
    }
    req.user = user;
    next();
  } catch (err) {
    logger.warn('Invalid token used', { error: err.message, ip: req.ip });
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// Security: Role-based authorization middleware
function authorizeRole(requiredRole) {
  return (req, res, next) => {
    if (!req.user) {
      logger.warn('Authorization check without authenticated user', { ip: req.ip });
      return res.status(401).json({ error: 'Authentication required' });
    }

    const roleHierarchy = { 'user': 1, 'gestor': 2, 'admin': 3 };
    const userRoleLevel = roleHierarchy[req.user.role] || 0;
    const requiredRoleLevel = roleHierarchy[requiredRole] || 0;

    if (userRoleLevel < requiredRoleLevel) {
      logger.warn('Insufficient permissions', {
        user: req.user.username,
        userRole: req.user.role,
        requiredRole,
        ip: req.ip,
        path: req.path
      });
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
}

// Security: Authentication routes
app.post('/api/auth/register', [
  body('username').isLength({ min: 3, max: 50 }).trim().escape().withMessage('Username must be 3-50 characters'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('role').isIn(['user', 'gestor', 'admin']).withMessage('Invalid role'),
  body('name').optional().isLength({ min: 2, max: 100 }).trim().escape(),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Registration validation failed', { errors: errors.array() });
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password, role } = req.body;
    const normalizedUsername = String(username || '').trim();
    const normalizedEmail = String(email || '').trim().toLowerCase();

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
        role: role || 'user',
        name: req.body.name || null
      });
    }

    const fallbackUser = {
      id: newUser?.id || Date.now().toString(),
      username: normalizedUsername,
      email: normalizedEmail,
      password_hash: hashedPassword,
      role: role || 'user',
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

    res.json({
      message: 'Login successful',
      token,
      user: sanitizeUserForResponse(user)
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
app.get('/api/flow-payments', authenticateToken, authorizeRole('user'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const payments = await listFlowPayments();
    res.json({ payments });
  } catch (error) {
    logger.error('Error listing flow payments', { error: error.message });
    res.status(500).json({ error: 'Failed to list flow payments' });
  }
});

app.post('/api/flow-payments/import', authenticateToken, authorizeRole('user'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const items = Array.isArray(req.body) ? req.body : (req.body?.payments || []);
    const normalized = items.map(item => ({
      id: String(item.id || crypto.randomUUID()),
      fornecedor: item.fornecedor || 'N/A',
      data: item.data || null,
      descricao: item.descricao || '',
      valor: Number(item.valor) || 0,
      centro: item.centro || '',
      categoria: item.categoria || '',
      assinatura: item.assinatura || null,
      created_at: new Date(),
      updated_at: new Date()
    }));
    await replaceFlowPayments(normalized);
    res.json({ success: true, count: normalized.length });
  } catch (error) {
    logger.error('Error importing flow payments', { error: error.message });
    res.status(500).json({ error: 'Failed to import flow payments' });
  }
});

app.post('/api/flow-payments', authenticateToken, authorizeRole('user'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const item = req.body || {};
    const payment = {
      id: String(item.id || crypto.randomUUID()),
      fornecedor: item.fornecedor || 'N/A',
      data: item.data || null,
      descricao: item.descricao || '',
      valor: Number(item.valor) || 0,
      centro: item.centro || '',
      categoria: item.categoria || '',
      assinatura: item.assinatura || null,
      created_at: new Date(),
      updated_at: new Date()
    };
    await upsertFlowPayment(payment);
    res.json({ success: true, payment });
  } catch (error) {
    logger.error('Error creating flow payment', { error: error.message });
    res.status(500).json({ error: 'Failed to create flow payment' });
  }
});

app.patch('/api/flow-payments/:id/sign', authenticateToken, authorizeRole('user'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const paymentId = req.params.id;
    const assinatura = req.body?.assinatura || null;
    const updated = await updateFlowPayment(paymentId, { assinatura });
    const payments = await listFlowPayments();
    const withChain = applyChainHashes(payments);
    await Promise.all(
      withChain
        .filter(p => p?.assinatura?.chain_hash)
        .map(p => updateFlowPayment(p.id, { assinatura: p.assinatura }))
    );
    const refreshed = withChain.find(p => String(p.id) === String(paymentId)) || updated;
    emitEventWebhook('payment_signed', {
      paymentId,
      user: req.user?.username || null,
      assinatura: refreshed?.assinatura || null
    });
    res.json({ success: true, payment: refreshed });
  } catch (error) {
    logger.error('Error signing flow payment', { error: error.message });
    res.status(500).json({ error: 'Failed to sign flow payment' });
  }
});

// Archived flow snapshots
app.get('/api/flow-archives', authenticateToken, authorizeRole('user'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const archives = await listFlowArchives();
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

app.post('/api/flow-archives', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const payments = await listFlowPayments();
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
      ? `Fluxo de Pagamentos (${labelDate}) - ${displayName}`
      : `Fluxo de Pagamentos (${labelDate})`;
    const withChain = applyChainHashes(payments);
    await Promise.all(
      withChain
        .filter(p => p?.assinatura?.chain_hash)
        .map(p => updateFlowPayment(p.id, { assinatura: p.assinatura }))
    );
    const archive = await createFlowArchive({
      id: crypto.randomUUID(),
      label,
      payments: withChain,
      createdBy: req.user?.username || null,
      count: withChain.length
    });
    await replaceFlowPayments([]);
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

app.delete('/api/flow-archives/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const archiveId = req.params.id;
    const deleted = await deleteFlowArchive(archiveId);
    res.json({ success: true, deleted: Number(deleted) || 0 });
  } catch (error) {
    logger.error('Error deleting flow archive', { error: error.message });
    res.status(500).json({ error: 'Failed to delete flow archive' });
  }
});

// Security: Protected route to sign a payment (requires gestor or admin)
app.post('/api/payments/:id/sign', authenticateToken, authorizeRole('gestor'), [
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
app.delete('/api/payments/:id', authenticateToken, authorizeRole('admin'), [
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
app.get('/api/auth/user-status', authenticateToken, (req, res) => {
  res.json({
    authenticated: true,
    user: sanitizeUserForResponse(req.user)
  });
});

// Admin: revoke all sessions for a user
app.post('/api/auth/revoke/:id', authenticateToken, authorizeRole('admin'), [
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
    res.json({ success: true });
  } catch (error) {
    logger.error('Failed to revoke sessions', { error: error.message });
    res.status(500).json({ success: false, error: 'Failed to revoke sessions' });
  }
});

// Self: revoke current sessions (logout everywhere)
app.post('/api/auth/revoke-self', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    await setUserSessionRevokedAfter(req.user?.id, new Date());
    res.json({ success: true });
  } catch (error) {
    logger.error('Failed to revoke own sessions', { error: error.message });
    res.status(500).json({ success: false, error: 'Failed to revoke sessions' });
  }
});

// Admin: list users
app.get('/api/users', authenticateToken, authorizeRole('admin'), async (req, res) => {
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
app.put('/api/users/:id', authenticateToken, authorizeRole('admin'), [
  param('id').isInt().withMessage('Valid user ID required'),
  body('username').optional().isLength({ min: 3, max: 50 }).trim().escape(),
  body('email').optional().isEmail().normalizeEmail(),
  body('role').optional().isIn(['user', 'gestor', 'admin']),
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

    res.json({ success: true, user: sanitizeUserForResponse(user) });
  } catch (error) {
    logger.error('Failed to update user', { error: error.message });
    res.status(500).json({ success: false, error: 'Failed to update user' });
  }
});

// Admin: delete user
app.delete('/api/users/:id', authenticateToken, authorizeRole('admin'), [
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

    res.json({ success: true });
  } catch (error) {
    logger.error('Failed to delete user', { error: error.message });
    res.status(500).json({ success: false, error: 'Failed to delete user' });
  }
});

// Admin: backup (users + flow + archives)
app.get('/api/backup', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    if (!isDbReady()) {
      return res.status(503).json({ error: 'Database not ready' });
    }
    const users = await listUsers();
    const payments = await listFlowPayments();
    const archives = await listFlowArchives();
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

// Admin: restore (users + flow + archives)
app.post('/api/restore', authenticateToken, authorizeRole('admin'), async (req, res) => {
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

    res.json({ success: true });
  } catch (error) {
    logger.error('Restore failed', { error: error.message });
    res.status(500).json({ error: 'Failed to restore backup' });
  }
});

// CSRF error handler
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  return next(err);
});

// Start server
async function startServer() {
  try {
    if (process.env.NODE_ENV === 'production') {
      if (!process.env.JWT_SECRET) {
        throw new Error('JWT_SECRET is required in production');
      }
    }
    await initDb();
    logger.info('Database connected');
  } catch (error) {
    logger.warn('Database unavailable, using in-memory fallback', { error: error.message });
  }
  await loadTokensFromDb();
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Conta Azul API integration ready');
  });
}

startServer().catch(error => {
  logger.error('Failed to start server', { error: error.message });
  process.exit(1);
});
