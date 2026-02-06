const { Sequelize, DataTypes, Op } = require('sequelize');

const connectionString = process.env.DATABASE_URL;
const useSSL = process.env.PG_SSL === 'true';

let sequelize = null;
let dbReady = false;

function getSequelize() {
  if (!sequelize) {
    if (!connectionString) {
      throw new Error('DATABASE_URL is required to initialize the database.');
    }

    sequelize = new Sequelize(connectionString, {
      logging: false,
      dialectOptions: useSSL ? { ssl: { rejectUnauthorized: false } } : {},
    });
  }
  return sequelize;
}

const UserModel = () => getSequelize().define('app_users', {
  id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true },
  username: { type: DataTypes.TEXT, unique: true, allowNull: false },
  email: { type: DataTypes.TEXT, unique: true, allowNull: false },
  password_hash: { type: DataTypes.TEXT, allowNull: false },
  role: { type: DataTypes.TEXT, allowNull: false },
  name: { type: DataTypes.TEXT },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
  last_login: { type: DataTypes.DATE },
}, { timestamps: false, freezeTableName: true });

const TokenModel = () => getSequelize().define('api_tokens', {
  service: { type: DataTypes.TEXT, primaryKey: true },
  access_token: { type: DataTypes.TEXT },
  refresh_token: { type: DataTypes.TEXT },
  expires_at: { type: DataTypes.DATE },
  updated_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, { timestamps: false, freezeTableName: true });

const FlowPaymentModel = () => getSequelize().define('flow_payments', {
  id: { type: DataTypes.TEXT, primaryKey: true },
  company: { type: DataTypes.TEXT },
  fornecedor: { type: DataTypes.TEXT, allowNull: false },
  data: { type: DataTypes.TEXT },
  descricao: { type: DataTypes.TEXT },
  valor: { type: DataTypes.DOUBLE },
  centro: { type: DataTypes.TEXT },
  categoria: { type: DataTypes.TEXT },
  assinatura: { type: DataTypes.JSONB },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
  updated_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, { timestamps: false, freezeTableName: true });

const FlowArchiveModel = () => getSequelize().define('flow_archives', {
  id: { type: DataTypes.TEXT, primaryKey: true },
  company: { type: DataTypes.TEXT },
  label: { type: DataTypes.TEXT, allowNull: false },
  payments: { type: DataTypes.JSONB, allowNull: false },
  created_by: { type: DataTypes.TEXT },
  count: { type: DataTypes.INTEGER },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, { timestamps: false, freezeTableName: true });

const WebhookModel = () => getSequelize().define('webhook_data', {
  id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true },
  source: { type: DataTypes.TEXT, allowNull: false },
  payload: { type: DataTypes.JSONB, allowNull: false },
  headers: { type: DataTypes.JSONB },
  received_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, { timestamps: false, freezeTableName: true });

const LoginAuditModel = () => getSequelize().define('audit_logins', {
  id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true },
  username: { type: DataTypes.TEXT },
  ip: { type: DataTypes.TEXT },
  success: { type: DataTypes.BOOLEAN, defaultValue: false },
  details: { type: DataTypes.TEXT },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, { timestamps: false, freezeTableName: true });

const AuditEventModel = () => getSequelize().define('audit_events', {
  id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true },
  action: { type: DataTypes.TEXT, allowNull: false },
  details: { type: DataTypes.TEXT },
  username: { type: DataTypes.TEXT },
  user_id: { type: DataTypes.BIGINT },
  ip: { type: DataTypes.TEXT },
  user_agent: { type: DataTypes.TEXT },
  metadata: { type: DataTypes.JSONB },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, { timestamps: false, freezeTableName: true });

const UserSessionModel = () => getSequelize().define('user_sessions', {
  user_id: { type: DataTypes.BIGINT, primaryKey: true },
  revoked_after: { type: DataTypes.DATE },
}, { timestamps: false, freezeTableName: true });

async function initDb() {
  const db = getSequelize();
  const maxAttempts = Number(process.env.DB_CONNECT_RETRIES || 5);
  const delayMs = Number(process.env.DB_CONNECT_RETRY_DELAY_MS || 2000);
  let lastError = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      await db.authenticate();
      UserModel();
      TokenModel();
      FlowPaymentModel();
      FlowArchiveModel();
      LoginAuditModel();
      AuditEventModel();
      UserSessionModel();
      WebhookModel();
      await db.sync();
      dbReady = true;
      return;
    } catch (error) {
      lastError = error;
      if (attempt < maxAttempts) {
        await new Promise(resolve => setTimeout(resolve, delayMs));
      }
    }
  }

  throw lastError;
}

function isDbReady() {
  return dbReady;
}

function mapUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    password_hash: row.password_hash,
    role: row.role,
    name: row.name,
    created_at: row.created_at,
    last_login: row.last_login,
  };
}

async function getUserByUsernameOrEmail(value) {
  const User = UserModel();
  const lookup = String(value || '').trim();
  const row = await User.findOne({
    where: {
      [Op.or]: [
        { username: { [Op.iLike]: lookup } },
        { email: { [Op.iLike]: lookup } }
      ]
    }
  });
  return mapUser(row);
}

async function getUserById(id) {
  const User = UserModel();
  const row = await User.findByPk(id);
  return mapUser(row);
}

async function findUserByUsernameOrEmailExcludingId(username, email, excludeId) {
  const User = UserModel();
  const usernameLookup = username ? String(username).trim() : null;
  const emailLookup = email ? String(email).trim() : null;
  const row = await User.findOne({
    where: {
      [Op.and]: [
        { id: { [Op.ne]: excludeId } },
        {
          [Op.or]: [
            usernameLookup ? { username: { [Op.iLike]: usernameLookup } } : null,
            emailLookup ? { email: { [Op.iLike]: emailLookup } } : null
          ].filter(Boolean)
        }
      ]
    }
  });
  return mapUser(row);
}

async function createUser({ username, email, passwordHash, role, name }) {
  const User = UserModel();
  const row = await User.create({
    username,
    email,
    password_hash: passwordHash,
    role,
    name: name || null,
  });
  return mapUser(row);
}

async function updateUserById(id, updates) {
  const User = UserModel();
  await User.update(updates, { where: { id } });
  return getUserById(id);
}

async function deleteUserById(id) {
  const User = UserModel();
  return User.destroy({ where: { id } });
}

async function listUsers() {
  const User = UserModel();
  const rows = await User.findAll();
  return rows.map(mapUser);
}

async function replaceUsers(users) {
  const User = UserModel();
  await User.destroy({ where: {}, truncate: true });
  if (users && users.length) {
    await User.bulkCreate(users);
  }
}

async function updateLastLogin(userId) {
  const User = UserModel();
  await User.update({ last_login: new Date() }, { where: { id: userId } });
}

async function getServiceToken(service) {
  const Token = TokenModel();
  const row = await Token.findByPk(service);
  return row ? row.toJSON() : null;
}

async function upsertServiceToken(service, accessToken, refreshToken, expiresAt) {
  const Token = TokenModel();
  await Token.upsert({
    service,
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_at: expiresAt || null,
    updated_at: new Date(),
  });
}

async function insertWebhook(source, payload, headers) {
  const Webhook = WebhookModel();
  await Webhook.create({
    source,
    payload,
    headers: headers || null
  });
}

async function insertLoginAudit({ username, ip, success, details }) {
  const Audit = LoginAuditModel();
  await Audit.create({
    username: username || null,
    ip: ip || null,
    success: !!success,
    details: details || null,
    created_at: new Date()
  });
}

async function listLoginAudits(limit = 200) {
  const Audit = LoginAuditModel();
  const rows = await Audit.findAll({
    order: [['created_at', 'DESC']],
    limit
  });
  return rows.map(r => r.toJSON());
}

async function insertAuditEvent({ action, details, username, userId, ip, userAgent, metadata }) {
  const Audit = AuditEventModel();
  await Audit.create({
    action,
    details: details || null,
    username: username || null,
    user_id: userId || null,
    ip: ip || null,
    user_agent: userAgent || null,
    metadata: metadata || null,
    created_at: new Date()
  });
}

async function listAuditEvents(limit = 200) {
  const Audit = AuditEventModel();
  const rows = await Audit.findAll({
    order: [['created_at', 'DESC']],
    limit
  });
  return rows.map(r => r.toJSON());
}

async function getUserSession(userId) {
  const Session = UserSessionModel();
  const row = await Session.findByPk(userId);
  return row ? row.toJSON() : null;
}

async function setUserSessionRevokedAfter(userId, revokedAfter) {
  const Session = UserSessionModel();
  await Session.upsert({
    user_id: userId,
    revoked_after: revokedAfter || null
  });
}

async function listFlowPayments(company = null) {
  const Flow = FlowPaymentModel();
  let where = {};
  if (company) {
    if (company === 'DMF') {
      where = { [Op.or]: [{ company }, { company: null }] };
    } else {
      where = { company };
    }
  }
  const rows = await Flow.findAll({ where, order: [['created_at', 'ASC']] });
  return rows.map(r => r.toJSON());
}

async function replaceFlowPayments(payments, company = null) {
  const Flow = FlowPaymentModel();
  if (company) {
    if (company === 'DMF') {
      await Flow.destroy({ where: { [Op.or]: [{ company }, { company: null }] } });
    } else {
      await Flow.destroy({ where: { company } });
    }
  } else {
    await Flow.destroy({ where: {}, truncate: true });
  }
  if (payments && payments.length) {
    for (const payment of payments) {
      await Flow.upsert(payment);
    }
  }
}

async function upsertFlowPayment(payment) {
  const Flow = FlowPaymentModel();
  await Flow.upsert({
    ...payment,
    updated_at: new Date()
  });
}

async function updateFlowPayment(id, updates, company = null) {
  const Flow = FlowPaymentModel();
  let where = { id };
  if (company) {
    if (company === 'DMF') {
      where = { id, [Op.or]: [{ company }, { company: null }] };
    } else {
      where = { id, company };
    }
  }
  await Flow.update({ ...updates, updated_at: new Date() }, { where });
  const row = await Flow.findOne({ where });
  return row ? row.toJSON() : null;
}

async function listFlowArchives(company = null) {
  const Archive = FlowArchiveModel();
  let where = {};
  if (company) {
    if (company === 'DMF') {
      where = { [Op.or]: [{ company }, { company: null }] };
    } else {
      where = { company };
    }
  }
  const rows = await Archive.findAll({ where, order: [['created_at', 'DESC']] });
  return rows.map(r => r.toJSON());
}

async function createFlowArchive({ id, label, payments, createdBy, count, company }) {
  const Archive = FlowArchiveModel();
  const row = await Archive.create({
    id,
    label,
    company: company || null,
    payments,
    created_by: createdBy || null,
    count: Number(count) || 0,
    created_at: new Date(),
  });
  return row ? row.toJSON() : null;
}

async function deleteFlowArchive(id) {
  const Archive = FlowArchiveModel();
  return Archive.destroy({ where: { id } });
}

async function replaceFlowArchives(archives) {
  const Archive = FlowArchiveModel();
  await Archive.destroy({ where: {}, truncate: true });
  if (archives && archives.length) {
    await Archive.bulkCreate(archives);
  }
}

module.exports = {
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
  insertAuditEvent,
  listAuditEvents,
  getUserSession,
  setUserSessionRevokedAfter,
  insertWebhook,
};
