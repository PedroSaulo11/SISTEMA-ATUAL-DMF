const { Sequelize, DataTypes, Op, literal } = require('sequelize');

let sequelize = null;
let dbReady = false;

function getSequelize() {
  if (!sequelize) {
    const connectionString = process.env.DATABASE_URL;
    const useSSL = process.env.PG_SSL === 'true';
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

function normalizeCompany(value) {
  const v = String(value || '').trim().toLowerCase();
  if (v === 'real energy' || v === 'real' || v === 'realenergy') return 'Real Energy';
  if (v === 'jfx') return 'JFX';
  if (v === 'dmf') return 'DMF';
  return value ? String(value).trim() : null;
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
  company: { type: DataTypes.TEXT, allowNull: false, defaultValue: 'DMF', primaryKey: true },
  fornecedor: { type: DataTypes.TEXT, allowNull: false },
  data: { type: DataTypes.TEXT },
  descricao: { type: DataTypes.TEXT },
  valor: { type: DataTypes.DOUBLE },
  centro: { type: DataTypes.TEXT },
  categoria: { type: DataTypes.TEXT },
  assinatura: { type: DataTypes.JSONB },
  version: { type: DataTypes.INTEGER, defaultValue: 0 },
  updated_by: { type: DataTypes.TEXT },
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

const RoleModel = () => getSequelize().define('app_roles', {
  name: { type: DataTypes.TEXT, primaryKey: true },
  permissions: { type: DataTypes.JSONB, allowNull: false },
  updated_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, { timestamps: false, freezeTableName: true });

const UserSessionModel = () => getSequelize().define('user_sessions', {
  user_id: { type: DataTypes.BIGINT, primaryKey: true },
  revoked_after: { type: DataTypes.DATE },
}, { timestamps: false, freezeTableName: true });

const UserRefreshSessionModel = () => getSequelize().define('app_user_refresh_sessions', {
  token_id: { type: DataTypes.TEXT, primaryKey: true },
  user_id: { type: DataTypes.BIGINT, allowNull: false },
  family_id: { type: DataTypes.TEXT, allowNull: false },
  expires_at: { type: DataTypes.DATE, allowNull: false },
  revoked_at: { type: DataTypes.DATE },
  rotated_at: { type: DataTypes.DATE },
  user_agent: { type: DataTypes.TEXT },
  ip: { type: DataTypes.TEXT },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, { timestamps: false, freezeTableName: true });

const UserCompanyModel = () => getSequelize().define('app_user_companies', {
  user_id: { type: DataTypes.BIGINT, primaryKey: true },
  company: { type: DataTypes.TEXT, primaryKey: true },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, { timestamps: false, freezeTableName: true });

const CenterCompanyModel = () => getSequelize().define('app_center_companies', {
  center_key: { type: DataTypes.TEXT, primaryKey: true },
  center_label: { type: DataTypes.TEXT, allowNull: false },
  company: { type: DataTypes.TEXT, allowNull: false },
  updated_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, { timestamps: false, freezeTableName: true });

function normalizeCenterKey(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizeCenterLabel(value) {
  return String(value || '').trim();
}

async function registerDiscoveredCenters(items, { transaction = null } = {}) {
  if (!Array.isArray(items) || !items.length) return 0;
  const Center = CenterCompanyModel();
  const unique = new Map();

  for (const item of items) {
    const label = normalizeCenterLabel(item?.center || item?.center_label || item?.centro);
    const key = normalizeCenterKey(item?.center_key || label);
    if (!label || !key) continue;
    const company = normalizeCompany(item?.company) || 'Outros';
    if (!unique.has(key)) {
      unique.set(key, { center_key: key, center_label: label, company, updated_at: new Date() });
    }
  }

  const keys = Array.from(unique.keys());
  if (!keys.length) return 0;

  const existing = await Center.findAll({
    attributes: ['center_key'],
    where: { center_key: { [Op.in]: keys } },
    transaction
  });
  const existingKeys = new Set(existing.map((row) => String(row.center_key || '').trim().toLowerCase()));
  const toInsert = keys.filter((k) => !existingKeys.has(k)).map((k) => unique.get(k));
  if (!toInsert.length) return 0;

  await Center.bulkCreate(toInsert, { transaction });
  return toInsert.length;
}

const BackupSnapshotModel = () => getSequelize().define('backup_snapshots', {
  id: { type: DataTypes.BIGINT, autoIncrement: true, primaryKey: true },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
  created_by: { type: DataTypes.TEXT },
  payload: { type: DataTypes.JSONB, allowNull: false },
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
      RoleModel();
      UserSessionModel();
      UserRefreshSessionModel();
      UserCompanyModel();
      CenterCompanyModel();
      BackupSnapshotModel();
      WebhookModel();
      await db.sync();
      await ensureDefaultRoles();
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

async function ensureDefaultRoles() {
  const Role = RoleModel();
  const defaults = [
    {
      name: 'admin',
      permissions: [
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
      ]
    },
    {
      name: 'gestor',
      permissions: [
        'sign_payments',
        'import_payments',
        'export_payments',
        'add_payments',
        'view_archives',
        'compare_archives',
        'audit_access',
        'audit_login_access'
      ]
    },
    { name: 'user', permissions: ['sign_payments'] }
  ];
  const existing = await Role.findAll();
  if (!existing.length) {
    await Role.bulkCreate(defaults.map(r => ({
      name: r.name,
      permissions: r.permissions,
      updated_at: new Date()
    })));
    return;
  }
  for (const role of defaults) {
    const row = await Role.findByPk(role.name);
    if (!row) {
      await Role.create({
        name: role.name,
        permissions: role.permissions,
        updated_at: new Date()
      });
      continue;
    }
    const currentPerms = Array.isArray(row.permissions) ? row.permissions : [];
    if (currentPerms.includes('all')) {
      await Role.update({
        permissions: role.permissions,
        updated_at: new Date()
      }, { where: { name: role.name } });
    }
  }
}

async function listRoles() {
  const Role = RoleModel();
  const rows = await Role.findAll();
  return rows.map(r => r.toJSON());
}

async function getRoleByName(name) {
  const Role = RoleModel();
  const row = await Role.findByPk(name);
  return row ? row.toJSON() : null;
}

async function upsertRole(name, permissions) {
  const Role = RoleModel();
  await Role.upsert({
    name,
    permissions: permissions || [],
    updated_at: new Date()
  });
  return getRoleByName(name);
}

async function deleteRoleByName(name) {
  const Role = RoleModel();
  return Role.destroy({ where: { name } });
}

async function replaceRoles(roles) {
  const Role = RoleModel();
  await Role.destroy({ where: {}, truncate: true });
  if (roles && roles.length) {
    await Role.bulkCreate(roles.map(r => ({
      name: r.name,
      permissions: r.permissions || [],
      updated_at: new Date()
    })));
  }
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
  const db = getSequelize();
  const normalizedAction = String(action || '').trim();
  if (!normalizedAction) return;
  let metadataJson = null;
  if (metadata && typeof metadata === 'object') {
    try {
      metadataJson = JSON.stringify(metadata);
    } catch (_) {
      metadataJson = null;
    }
  }
  const normalizedUserId = Number.isFinite(Number(userId)) ? Number(userId) : null;
  const payload = {
    action: normalizedAction.slice(0, 120),
    details: details == null ? null : String(details).slice(0, 2000),
    username: username == null ? null : String(username).slice(0, 255),
    user_id: normalizedUserId,
    ip: ip == null ? null : String(ip).slice(0, 255),
    user_agent: userAgent == null ? null : String(userAgent).slice(0, 1024),
    metadata: metadataJson,
    created_at: new Date()
  };
  try {
    await db.query(
      `
        INSERT INTO audit_events
          (action, details, username, user_id, ip, user_agent, metadata, created_at)
        VALUES
          (:action, :details, :username, :user_id, :ip, :user_agent, CAST(:metadata AS jsonb), :created_at)
      `,
      {
        replacements: {
          action: payload.action,
          details: payload.details,
          username: payload.username,
          user_id: payload.user_id,
          ip: payload.ip,
          user_agent: payload.user_agent,
          metadata: payload.metadata,
          created_at: payload.created_at
        }
      }
    );
    return;
  } catch (error) {
    const message = String(error?.message || '').toLowerCase();
    // Some managed DB setups grant table INSERT but not sequence usage.
    // Fallback to explicit id allocation under table lock to preserve audit writes.
    if (!message.includes('permission denied for sequence audit_events_id_seq')) {
      throw error;
    }
  }

  await db.transaction(async (transaction) => {
    await db.query('LOCK TABLE audit_events IN EXCLUSIVE MODE', { transaction });
    await db.query(
      `
        INSERT INTO audit_events
          (id, action, details, username, user_id, ip, user_agent, metadata, created_at)
        SELECT
          COALESCE(MAX(id), 0) + 1,
          :action, :details, :username, :user_id, :ip, :user_agent, CAST(:metadata AS jsonb), :created_at
        FROM audit_events
      `,
      {
        transaction,
        replacements: {
          action: payload.action,
          details: payload.details,
          username: payload.username,
          user_id: payload.user_id,
          ip: payload.ip,
          user_agent: payload.user_agent,
          metadata: payload.metadata,
          created_at: payload.created_at
        }
      }
    );
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

async function createUserRefreshSession({ tokenId, userId, familyId, expiresAt, userAgent = null, ip = null }) {
  const Session = UserRefreshSessionModel();
  await Session.create({
    token_id: String(tokenId),
    user_id: Number(userId),
    family_id: String(familyId),
    expires_at: expiresAt,
    user_agent: userAgent || null,
    ip: ip || null,
    created_at: new Date()
  });
  const row = await Session.findByPk(String(tokenId));
  return row ? row.toJSON() : null;
}

async function getUserRefreshSession(tokenId) {
  const Session = UserRefreshSessionModel();
  const row = await Session.findByPk(String(tokenId));
  return row ? row.toJSON() : null;
}

async function rotateUserRefreshSession({ oldTokenId, newTokenId, userId, familyId, expiresAt, userAgent = null, ip = null }) {
  const db = getSequelize();
  const Session = UserRefreshSessionModel();
  return db.transaction(async (transaction) => {
    const [updated] = await Session.update({
      rotated_at: new Date()
    }, {
      where: {
        token_id: String(oldTokenId),
        user_id: Number(userId),
        family_id: String(familyId),
        revoked_at: { [Op.is]: null },
        rotated_at: { [Op.is]: null }
      },
      transaction
    });
    if (!updated) return null;
    await Session.create({
      token_id: String(newTokenId),
      user_id: Number(userId),
      family_id: String(familyId),
      expires_at: expiresAt,
      user_agent: userAgent || null,
      ip: ip || null,
      created_at: new Date()
    }, { transaction });
    const row = await Session.findByPk(String(newTokenId), { transaction });
    return row ? row.toJSON() : null;
  });
}

async function revokeUserRefreshSessionsByUser(userId) {
  const Session = UserRefreshSessionModel();
  return Session.update({
    revoked_at: new Date()
  }, {
    where: {
      user_id: Number(userId),
      revoked_at: { [Op.is]: null }
    }
  });
}

async function revokeUserRefreshSessionsByFamily(familyId) {
  const Session = UserRefreshSessionModel();
  return Session.update({
    revoked_at: new Date()
  }, {
    where: {
      family_id: String(familyId),
      revoked_at: { [Op.is]: null }
    }
  });
}

async function listActiveUserRefreshSessions(limit = 200) {
  const db = getSequelize();
  const safeLimit = Math.max(1, Math.min(Number(limit) || 200, 1000));
  const rows = await db.query(
    `
      SELECT
        s.token_id,
        s.user_id,
        s.family_id,
        s.expires_at,
        s.user_agent,
        s.ip,
        s.created_at,
        u.username,
        u.email,
        u.name,
        u.role
      FROM app_user_refresh_sessions s
      LEFT JOIN app_users u ON u.id = s.user_id
      WHERE s.revoked_at IS NULL
        AND s.rotated_at IS NULL
        AND s.expires_at > NOW()
      ORDER BY s.created_at DESC
      LIMIT :limit
    `,
    {
      replacements: { limit: safeLimit },
      type: Sequelize.QueryTypes.SELECT
    }
  );

  return (rows || []).map((row) => ({
    token_id: row.token_id,
    user_id: Number(row.user_id),
    family_id: row.family_id,
    expires_at: row.expires_at ? new Date(row.expires_at).toISOString() : null,
    user_agent: row.user_agent || null,
    ip: row.ip || null,
    created_at: row.created_at ? new Date(row.created_at).toISOString() : null,
    username: row.username || null,
    email: row.email || null,
    name: row.name || null,
    role: row.role || null
  }));
}

async function listFlowPayments(company = null) {
  const Flow = FlowPaymentModel();
  let where = {};
  if (company) {
    where = { company: normalizeCompany(company) || company };
  }
  const rows = await Flow.findAll({
    where,
    order: [['created_at', 'ASC'], ['id', 'ASC']]
  });
  return rows.map(r => r.toJSON());
}

async function getFlowPaymentsStats(companies = null) {
  const db = getSequelize();
  const list = Array.isArray(companies) ? companies.map(normalizeCompany).filter(Boolean) : null;
  const whereSql = list && list.length
    ? `(company = ANY(:companies))`
    : `TRUE`;

  const rows = await db.query(
    `
      SELECT
        COALESCE(NULLIF(TRIM(company), ''), 'DMF') AS company,
        COUNT(*)::bigint AS count,
        SUM(ABS(COALESCE(valor, 0)))::double precision AS total_abs,
        SUM(CASE WHEN assinatura IS NOT NULL THEN 1 ELSE 0 END)::bigint AS signed,
        SUM(CASE WHEN assinatura IS NULL THEN 1 ELSE 0 END)::bigint AS pending,
        MAX(updated_at) AS last_updated_at
      FROM flow_payments
      WHERE ${whereSql}
      GROUP BY COALESCE(NULLIF(TRIM(company), ''), 'DMF')
      ORDER BY COALESCE(NULLIF(TRIM(company), ''), 'DMF') ASC
    `,
    {
      replacements: {
        companies: list || [],
      },
      type: Sequelize.QueryTypes.SELECT
    }
  );

  return (rows || []).map((r) => ({
    company: normalizeCompany(r.company) || r.company,
    count: Number(r.count || 0) || 0,
    total_abs: Number(r.total_abs || 0) || 0,
    signed: Number(r.signed || 0) || 0,
    pending: Number(r.pending || 0) || 0,
    last_updated_at: r.last_updated_at ? new Date(r.last_updated_at).toISOString() : null,
  }));
}

async function replaceFlowPayments(payments, company = null) {
  const Flow = FlowPaymentModel();
  const db = getSequelize();
  await db.transaction(async (transaction) => {
    let scopeWhere = {};
    if (company) {
      scopeWhere = { company: normalizeCompany(company) || company };
    }

    const existingRows = await Flow.findAll({
      where: scopeWhere,
      transaction
    });
    const existingById = new Map(
      existingRows.map((row) => {
        const item = row.toJSON();
        const key = `${normalizeCompany(item.company) || item.company || 'DMF'}:${String(item.id)}`;
        return [key, item];
      })
    );

    const merged = (payments || []).map((payment) => {
      const id = String(payment.id || '');
      const normalizedCompany = normalizeCompany(payment.company || company) || 'DMF';
      const existing = existingById.get(`${normalizedCompany}:${id}`);
      if (!existing) {
        return {
          ...payment,
          company: normalizedCompany,
          version: Number.isFinite(payment.version) ? Number(payment.version) : 0
        };
      }

      // Preserve assinatura/version when import payload is stale and avoid regressing ordering timestamps.
      const next = { ...payment };
      if (!next.assinatura && existing.assinatura) {
        next.assinatura = existing.assinatura;
      }
      next.company = normalizedCompany;
      const incomingVersion = Number.isFinite(next.version) ? Number(next.version) : 0;
      const existingVersion = Number(existing.version || 0);
      next.version = Math.max(incomingVersion, existingVersion);
      next.created_at = existing.created_at || next.created_at || new Date();
      next.updated_at = new Date();
      return next;
    });

    await registerDiscoveredCenters(
      merged.map((item) => ({ center: item?.centro, company: item?.company })),
      { transaction }
    );

    if (company) {
      await Flow.destroy({ where: scopeWhere, transaction });
    } else {
      await Flow.destroy({ where: {}, truncate: true, transaction });
    }

    if (merged.length) {
      await Flow.bulkCreate(merged, { transaction });
    }
  });
}

async function upsertFlowPayment(payment) {
  const Flow = FlowPaymentModel();
  const company = normalizeCompany(payment?.company) || 'DMF';
  // Preserve created_at for stable ordering across devices/imports.
  let createdAt = payment?.created_at || null;
  try {
    if (payment?.id) {
      const existing = await Flow.findOne({
        where: {
          id: String(payment.id),
          company
        }
      });
      if (existing?.created_at) {
        createdAt = existing.created_at;
      }
    }
  } catch (_) {
    // ignore lookup errors; upsert below will surface real issues.
  }
  await Flow.upsert({
    ...payment,
    company,
    created_at: createdAt || new Date(),
    updated_at: new Date()
  });
  await registerDiscoveredCenters([{ center: payment?.centro, company }]);
}

async function updateFlowPaymentWithVersion(id, updates, expectedVersion, company = null) {
  const Flow = FlowPaymentModel();
  const safeUpdates = { ...(updates || {}) };
  delete safeUpdates.created_at; // never mutate created_at (ordering key)
  let where = { id, version: expectedVersion };
  if (company) {
    where = { id, version: expectedVersion, company: normalizeCompany(company) || company };
  }
  const [count] = await Flow.update({
    ...safeUpdates,
    version: expectedVersion + 1,
    updated_at: new Date()
  }, { where });
  if (!count) return null;
  const row = await Flow.findOne({ where: { id, ...(company ? { company: normalizeCompany(company) || company } : {}) } });
  if (row?.centro) {
    await registerDiscoveredCenters([{ center: row.centro, company: row.company }]);
  }
  return row ? row.toJSON() : null;
}

async function updateFlowPayment(id, updates, company = null) {
  const Flow = FlowPaymentModel();
  let where = { id };
  if (company) {
    where = { id, company: normalizeCompany(company) || company };
  }
  await Flow.update({ ...updates, updated_at: new Date() }, { where });
  const row = await Flow.findOne({ where });
  if (row?.centro) {
    await registerDiscoveredCenters([{ center: row.centro, company: row.company }]);
  }
  return row ? row.toJSON() : null;
}

async function getFlowPaymentById(id, company = null) {
  const Flow = FlowPaymentModel();
  let where = { id };
  if (company) {
    where = { id, company: normalizeCompany(company) || company };
  }
  const row = await Flow.findOne({ where });
  return row ? row.toJSON() : null;
}

async function deleteFlowPayment(id, company = null) {
  const Flow = FlowPaymentModel();
  let where = { id };
  if (company) {
    where = { id, company: normalizeCompany(company) || company };
  }
  const row = await Flow.findOne({ where });
  if (!row) return null;
  const data = row.toJSON();
  await Flow.destroy({ where });
  return data;
}

async function signFlowPaymentIfUnsigned(id, assinatura, company = null) {
  const Flow = FlowPaymentModel();
  let where = { id, assinatura: { [Op.is]: null } };
  if (company) {
    where = { id, assinatura: { [Op.is]: null }, company: normalizeCompany(company) || company };
  }
  const [count] = await Flow.update({
    assinatura,
    version: literal('"version" + 1'),
    updated_at: new Date()
  }, { where });
  if (!count) {
    return null;
  }
  const row = await Flow.findOne({ where: { id, ...(company ? { company: normalizeCompany(company) || company } : {}) } });
  return row ? row.toJSON() : null;
}

async function validateDbSchema() {
  if (!dbReady) {
    return { ok: false, reason: 'db_not_ready', missing: [] };
  }
  const qi = getSequelize().getQueryInterface();
  const checks = [
    { table: 'flow_payments', columns: ['id', 'company', 'assinatura', 'version', 'updated_at'] },
    { table: 'app_roles', columns: ['name', 'permissions'] },
    { table: 'app_center_companies', columns: ['center_key', 'center_label', 'company'] },
    { table: 'app_user_companies', columns: ['user_id', 'company'] },
    { table: 'app_user_refresh_sessions', columns: ['token_id', 'user_id', 'family_id', 'expires_at'] }
  ];
  const missing = [];
  for (const item of checks) {
    try {
      const desc = await qi.describeTable(item.table);
      for (const col of item.columns) {
        if (!Object.prototype.hasOwnProperty.call(desc, col)) {
          missing.push(`${item.table}.${col}`);
        }
      }
    } catch (_) {
      missing.push(item.table);
    }
  }
  try {
    const pkRows = await getSequelize().query(
      `
        SELECT kcu.column_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
          ON tc.constraint_name = kcu.constraint_name
         AND tc.table_schema = kcu.table_schema
        WHERE tc.table_name = 'flow_payments'
          AND tc.constraint_type = 'PRIMARY KEY'
        ORDER BY kcu.ordinal_position ASC
      `,
      { type: Sequelize.QueryTypes.SELECT }
    );
    const pkCols = (pkRows || []).map(r => String(r.column_name || ''));
    if (!(pkCols.length === 2 && pkCols[0] === 'company' && pkCols[1] === 'id')) {
      missing.push('flow_payments.pk(company,id)');
    }
  } catch (_) {
    missing.push('flow_payments.pk(company,id)');
  }
  return { ok: missing.length === 0, missing };
}

async function listFlowArchives(company = null) {
  const Archive = FlowArchiveModel();
  let where = {};
  if (company) {
    where = { company: normalizeCompany(company) || company };
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
  await registerDiscoveredCenters(
    (Array.isArray(payments) ? payments : []).map((item) => ({
      center: item?.centro,
      company: item?.company || company
    }))
  );
  return row ? row.toJSON() : null;
}

async function getFlowArchiveById(id) {
  const Archive = FlowArchiveModel();
  const row = await Archive.findByPk(String(id));
  return row ? row.toJSON() : null;
}

async function updateFlowArchivePayments(id, payments) {
  const Archive = FlowArchiveModel();
  await Archive.update({
    payments,
    count: Array.isArray(payments) ? payments.length : 0
  }, { where: { id: String(id) } });
  const row = await Archive.findByPk(String(id));
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
    const discovered = [];
    archives.forEach((archive) => {
      const payments = Array.isArray(archive?.payments) ? archive.payments : [];
      payments.forEach((item) => {
        discovered.push({
          center: item?.centro,
          company: item?.company || archive?.company
        });
      });
    });
    await registerDiscoveredCenters(discovered);
  }
}

async function listUserCompanies(userId) {
  const Access = UserCompanyModel();
  const rows = await Access.findAll({ where: { user_id: userId } });
  return rows.map(r => r.company);
}

async function replaceUserCompanies(userId, companies) {
  const Access = UserCompanyModel();
  await Access.destroy({ where: { user_id: userId } });
  if (companies && companies.length) {
    await Access.bulkCreate(companies.map(company => ({
      user_id: userId,
      company,
      created_at: new Date()
    })));
  }
}

async function listCenterCompanies() {
  const Center = CenterCompanyModel();
  const rows = await Center.findAll();
  const fromTable = rows.map(r => r.toJSON());
  const merged = new Map();

  fromTable.forEach((item) => {
    const key = normalizeCenterKey(item.center_key || item.center_label);
    const label = normalizeCenterLabel(item.center_label || item.center_key);
    const company = normalizeCompany(item.company) || 'Outros';
    if (!key || !label) return;
    merged.set(key, { center_key: key, center_label: label, company, updated_at: item.updated_at || null });
  });

  try {
    const Flow = FlowPaymentModel();
    const payments = await Flow.findAll({
      attributes: ['centro', 'company', 'updated_at'],
      where: {
        centro: { [Op.not]: null }
      }
    });
    payments.forEach((item) => {
      const label = normalizeCenterLabel(item.centro);
      const key = normalizeCenterKey(label);
      if (!label || !key || merged.has(key)) return;
      const company = normalizeCompany(item.company) || 'Outros';
      merged.set(key, {
        center_key: key,
        center_label: label,
        company,
        updated_at: item.updated_at || null
      });
    });
  } catch (_) {
    // ignore fallback errors; table values are already returned above.
  }

  try {
    const Archive = FlowArchiveModel();
    const archives = await Archive.findAll({ attributes: ['company', 'payments'] });
    archives.forEach((archiveRow) => {
      const archive = archiveRow.toJSON ? archiveRow.toJSON() : archiveRow;
      const company = normalizeCompany(archive?.company) || 'Outros';
      const payments = Array.isArray(archive?.payments) ? archive.payments : [];
      payments.forEach((item) => {
        const label = normalizeCenterLabel(item?.centro);
        const key = normalizeCenterKey(label);
        if (!label || !key || merged.has(key)) return;
        merged.set(key, {
          center_key: key,
          center_label: label,
          company,
          updated_at: null
        });
      });
    });
  } catch (_) {
    // ignore fallback errors; centers from archives are best-effort enrichment.
  }

  return Array.from(merged.values());
}

async function upsertCenterCompany(centerKey, centerLabel, company) {
  const Center = CenterCompanyModel();
  await Center.upsert({
    center_key: centerKey,
    center_label: centerLabel,
    company,
    updated_at: new Date()
  });
  const row = await Center.findByPk(centerKey);
  return row ? row.toJSON() : null;
}

async function bulkUpsertCenterCompanies(items) {
  if (!Array.isArray(items) || !items.length) return 0;
  let count = 0;
  for (const item of items) {
    const centerKey = String(item.center_key || item.center || '').trim().toLowerCase();
    const centerLabel = String(item.center_label || item.center || '').trim();
    const company = String(item.company || '').trim();
    if (!centerKey || !centerLabel || !company) continue;
    await upsertCenterCompany(centerKey, centerLabel, company);
    count += 1;
  }
  return count;
}

async function insertBackupSnapshot({ createdBy, payload }) {
  const Backup = BackupSnapshotModel();
  const row = await Backup.create({
    created_by: createdBy || null,
    payload,
    created_at: new Date()
  });
  return row ? row.toJSON() : null;
}

async function listBackupSnapshots(limit = 20) {
  const Backup = BackupSnapshotModel();
  const rows = await Backup.findAll({
    order: [['created_at', 'DESC']],
    limit
  });
  return rows.map(r => r.toJSON());
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
  getFlowPaymentsStats,
  replaceFlowPayments,
  upsertFlowPayment,
  updateFlowPaymentWithVersion,
  updateFlowPayment,
  getFlowPaymentById,
  deleteFlowPayment,
  signFlowPaymentIfUnsigned,
  listFlowArchives,
  createFlowArchive,
  getFlowArchiveById,
  updateFlowArchivePayments,
  deleteFlowArchive,
  replaceFlowArchives,
  listUserCompanies,
  replaceUserCompanies,
  listCenterCompanies,
  upsertCenterCompany,
  bulkUpsertCenterCompanies,
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
  createUserRefreshSession,
  getUserRefreshSession,
  rotateUserRefreshSession,
  revokeUserRefreshSessionsByUser,
  revokeUserRefreshSessionsByFamily,
  listActiveUserRefreshSessions,
  insertWebhook,
  validateDbSchema,
};
