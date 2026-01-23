require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// Serve static files
app.use(express.static(__dirname));

// In-memory storage for tokens (in production, use a database or secure storage)
let accessToken = process.env.CONTA_AZUL_ACCESS_TOKEN;
let refreshToken = process.env.CONTA_AZUL_REFRESH_TOKEN;
let tokenExpiry = null; // Will be set based on JWT expiry

// OAuth2 Configuration
const CLIENT_ID = process.env.CONTA_AZUL_CLIENT_ID;
const CLIENT_SECRET = process.env.CONTA_AZUL_CLIENT_SECRET;
const TOKEN_URL = process.env.CONTA_AZUL_TOKEN_URL;

// Cobli Configuration
const COBLI_API_BASE_URL = process.env.COBLI_API_BASE_URL;
const COBLI_API_TOKEN = process.env.COBLI_API_TOKEN;
const COBLI_AUTH_HEADER = process.env.COBLI_AUTH_HEADER || 'Authorization';
const COBLI_AUTH_SCHEME = process.env.COBLI_AUTH_SCHEME || 'Bearer';
const COBLI_WEBHOOK_SECRET = process.env.COBLI_WEBHOOK_SECRET;
const COBLI_WEBHOOK_SIGNATURE_HEADER = process.env.COBLI_WEBHOOK_SIGNATURE_HEADER;

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

  return axios({
    method,
    url,
    headers,
    params: options.params,
    data: options.data
  });
}

// Function to decode JWT and get expiry
function getTokenExpiry(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    return payload.exp * 1000; // Convert to milliseconds
  } catch (error) {
    console.error('Error decoding token:', error);
    return null;
  }
}

// Initialize token expiry on startup
if (accessToken) {
  tokenExpiry = getTokenExpiry(accessToken);
}

// Function to refresh token
async function refreshAccessToken() {
  if (!refreshToken) {
    throw new Error('No refresh token available');
  }

  try {
    const authHeader = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

    const response = await axios.post(TOKEN_URL, new URLSearchParams({
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

    console.log('Token refreshed successfully');
  } catch (error) {
    console.error('Error refreshing token:', error.response?.data || error.message);
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
    throw new Error('No access token available. Please authenticate first.');
  }

  if (Date.now() >= tokenExpiry - 60000) { // Refresh 1 minute before expiry
    await refreshAccessToken();
  }
}

// Route to fetch payments from Conta Azul API
app.get('/api/payments', async (req, res) => {
  try {
    await ensureValidToken();

    const response = await axios.get('https://api.contaazul.com/v1/pagamentos', {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      }
    });

    res.json(response.data);
  } catch (error) {
    console.error('Error fetching payments:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to fetch payments from Conta Azul API' });
  }
});

// Cobli health check
app.get('/api/cobli/health', (req, res) => {
  res.json({
    configured: !!COBLI_API_BASE_URL && !!COBLI_API_TOKEN,
    base_url: COBLI_API_BASE_URL || null
  });
});

// Cobli generic proxy (use ?path=/endpoint and optional query params)
app.all('/api/cobli/proxy', async (req, res) => {
  try {
    const path = req.query.path;
    if (!path) {
      return res.status(400).json({ error: 'Missing required query param: path' });
    }

    const { path: _, ...params } = req.query;
    const response = await cobliRequest(req.method, path, {
      params,
      data: req.body
    });

    res.status(response.status).json(response.data);
  } catch (error) {
    console.error('Cobli proxy error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to call Cobli API' });
  }
});

// Cobli webhook
app.post('/webhooks/cobli', (req, res) => {
  const verified = verifyCobliSignature(req);

  if (!verified) {
    return res.status(401).json({ error: 'Invalid webhook signature' });
  }

  console.log('Cobli webhook received:', req.body);
  res.status(200).json({ ok: true });
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
    token_expiry: tokenExpiry
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Conta Azul API integration ready');
});
