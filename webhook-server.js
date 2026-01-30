require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const { initDb, insertWebhook } = require('./db');

const app = express();
const PORT = process.env.WEBHOOK_PORT || 3002;

app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.get('/webhooks/health', (req, res) => {
  res.json({ ok: true });
});

function verifySignature(req, secret, headerName) {
  if (!secret) return true;
  const signature = req.get(headerName);
  if (!signature || !req.rawBody) return false;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(req.rawBody)
    .digest('hex');
  const normalized = signature.startsWith('sha256=')
    ? signature.slice('sha256='.length)
    : signature;
  return normalized === expected;
}

app.post('/webhooks/:source', async (req, res) => {
  try {
    const source = req.params.source;
    if (source === 'cobli') {
      const ok = verifySignature(
        req,
        process.env.COBLI_WEBHOOK_SECRET,
        process.env.COBLI_WEBHOOK_SIGNATURE_HEADER || 'X-Cobli-Signature'
      );
      if (!ok) return res.status(401).json({ error: 'Invalid webhook signature' });
    }
    if (source === 'contaazul') {
      const ok = verifySignature(
        req,
        process.env.CONTA_AZUL_WEBHOOK_SECRET,
        process.env.CONTA_AZUL_WEBHOOK_SIGNATURE_HEADER || 'X-ContaAzul-Signature'
      );
      if (!ok) return res.status(401).json({ error: 'Invalid webhook signature' });
    }

    await insertWebhook(req.params.source, req.body, req.headers);
    res.status(200).json({ ok: true });
  } catch (error) {
    console.error('Webhook insert failed:', error.message);
    res.status(500).json({ error: 'Failed to store webhook payload' });
  }
});

async function startWebhookServer() {
  await initDb();
  app.listen(PORT, () => {
    console.log(`Webhook server listening on http://localhost:${PORT}`);
  });
}

startWebhookServer().catch(error => {
  console.error('Failed to start webhook server:', error.message);
  process.exit(1);
});
