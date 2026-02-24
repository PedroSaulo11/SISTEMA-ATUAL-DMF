/* eslint-disable no-console */
const { Client } = require('pg');

function required(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) throw new Error(`Missing required env: ${name}`);
  return value;
}

function identifier(name) {
  return `"${String(name).replace(/"/g, '""')}"`;
}

async function main() {
  const databaseUrl = required('DB_ADMIN_URL');
  const appRole = required('DB_APP_ROLE');
  const ssl = String(process.env.PG_SSL || '').trim().toLowerCase() === 'true';

  const client = new Client({
    connectionString: databaseUrl,
    ssl: ssl ? { rejectUnauthorized: false } : undefined
  });

  await client.connect();
  try {
    const role = identifier(appRole);
    const sql = [
      `GRANT INSERT, SELECT ON TABLE audit_events TO ${role}`,
      `GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO ${role}`,
      `GRANT INSERT, SELECT ON TABLE audit_logins TO ${role}`,
      `GRANT USAGE, SELECT ON SEQUENCE audit_logins_id_seq TO ${role}`
    ];
    for (const stmt of sql) {
      await client.query(stmt);
      console.log(`[db-grant] ok ${stmt}`);
    }
    console.log(`[db-grant] PASS role=${appRole}`);
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error('[db-grant] FAIL', err && err.stack ? err.stack : err);
  process.exit(1);
});

