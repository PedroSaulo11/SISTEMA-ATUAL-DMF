require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// In-memory storage for tokens (in production, use a database or secure storage)
let accessToken = process.env.CONTA_AZUL_ACCESS_TOKEN;
let refreshToken = process.env.CONTA_AZUL_REFRESH_TOKEN;
let tokenExpiry = null; // Will be set based on JWT expiry

// OAuth2 Configuration
const CLIENT_ID = process.env.CONTA_AZUL_CLIENT_ID;
const CLIENT_SECRET = process.env.CONTA_AZUL_CLIENT_SECRET;
const TOKEN_URL = process.env.CONTA_AZUL_TOKEN_URL;

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
