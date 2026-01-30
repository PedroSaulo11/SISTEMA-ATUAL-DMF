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

const WebhookModel = () => getSequelize().define('webhook_data', {
  id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true },
  source: { type: DataTypes.TEXT, allowNull: false },
  payload: { type: DataTypes.JSONB, allowNull: false },
  headers: { type: DataTypes.JSONB },
  received_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
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
  updateLastLogin,
  getServiceToken,
  upsertServiceToken,
  insertWebhook,
};
