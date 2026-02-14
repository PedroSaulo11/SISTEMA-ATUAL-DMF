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

const BudgetLimitModel = () => getSequelize().define('budget_limits', {
  month_key: { type: DataTypes.TEXT, primaryKey: true }, // YYYY-MM
  company: { type: DataTypes.TEXT, primaryKey: true },
  limit_value: { type: DataTypes.DOUBLE, allowNull: false, defaultValue: 0 },
  updated_by: { type: DataTypes.TEXT },
  updated_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, { timestamps: false, freezeTableName: true });

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
      UserCompanyModel();
      CenterCompanyModel();
      BudgetLimitModel();
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
  const rows = await Flow.findAll({
    where,
    order: [['created_at', 'ASC'], ['id', 'ASC']]
  });
  return rows.map(r => r.toJSON());
}

async function replaceFlowPayments(payments, company = null) {
  const Flow = FlowPaymentModel();
  const db = getSequelize();
  await db.transaction(async (transaction) => {
    let scopeWhere = {};
    if (company) {
      if (company === 'DMF') {
        scopeWhere = { [Op.or]: [{ company }, { company: null }] };
      } else {
        scopeWhere = { company };
      }
    }

    const existingRows = await Flow.findAll({
      where: scopeWhere,
      transaction
    });
    const existingById = new Map(existingRows.map((row) => [String(row.id), row.toJSON()]));

    const merged = (payments || []).map((payment) => {
      const id = String(payment.id || '');
      const existing = existingById.get(id);
      if (!existing) {
        return {
          ...payment,
          version: Number.isFinite(payment.version) ? Number(payment.version) : 0
        };
      }

      // Preserve assinatura/version when import payload is stale and avoid regressing ordering timestamps.
      const next = { ...payment };
      if (!next.assinatura && existing.assinatura) {
        next.assinatura = existing.assinatura;
      }
      const incomingVersion = Number.isFinite(next.version) ? Number(next.version) : 0;
      const existingVersion = Number(existing.version || 0);
      next.version = Math.max(incomingVersion, existingVersion);
      next.created_at = existing.created_at || next.created_at || new Date();
      next.updated_at = new Date();
      return next;
    });

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
  // Preserve created_at for stable ordering across devices/imports.
  let createdAt = payment?.created_at || null;
  try {
    if (payment?.id) {
      const existing = await Flow.findByPk(String(payment.id));
      if (existing?.created_at) {
        createdAt = existing.created_at;
      }
    }
  } catch (_) {
    // ignore lookup errors; upsert below will surface real issues.
  }
  await Flow.upsert({
    ...payment,
    created_at: createdAt || new Date(),
    updated_at: new Date()
  });
}

async function updateFlowPaymentWithVersion(id, updates, expectedVersion, company = null) {
  const Flow = FlowPaymentModel();
  const safeUpdates = { ...(updates || {}) };
  delete safeUpdates.created_at; // never mutate created_at (ordering key)
  let where = { id, version: expectedVersion };
  if (company) {
    if (company === 'DMF') {
      where = { id, version: expectedVersion, [Op.or]: [{ company }, { company: null }] };
    } else {
      where = { id, version: expectedVersion, company };
    }
  }
  const [count] = await Flow.update({
    ...safeUpdates,
    version: expectedVersion + 1,
    updated_at: new Date()
  }, { where });
  if (!count) return null;
  const row = await Flow.findOne({ where: { id, ...(company ? (company === 'DMF' ? { [Op.or]: [{ company }, { company: null }] } : { company }) : {}) } });
  return row ? row.toJSON() : null;
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

async function getFlowPaymentById(id, company = null) {
  const Flow = FlowPaymentModel();
  let where = { id };
  if (company) {
    if (company === 'DMF') {
      where = { id, [Op.or]: [{ company }, { company: null }] };
    } else {
      where = { id, company };
    }
  }
  const row = await Flow.findOne({ where });
  return row ? row.toJSON() : null;
}

async function signFlowPaymentIfUnsigned(id, assinatura, company = null) {
  const Flow = FlowPaymentModel();
  let where = { id, assinatura: { [Op.is]: null } };
  if (company) {
    if (company === 'DMF') {
      where = { id, assinatura: { [Op.is]: null }, [Op.or]: [{ company }, { company: null }] };
    } else {
      where = { id, assinatura: { [Op.is]: null }, company };
    }
  }
  const [count] = await Flow.update({
    assinatura,
    version: literal('"version" + 1'),
    updated_at: new Date()
  }, { where });
  if (!count) {
    return null;
  }
  const row = await Flow.findOne({ where: { id, ...(company ? (company === 'DMF' ? { [Op.or]: [{ company }, { company: null }] } : { company }) : {}) } });
  return row ? row.toJSON() : null;
}

function normalizeCompany(value) {
  const v = String(value || '').trim().toLowerCase();
  if (v === 'real energy' || v === 'real' || v === 'realenergy') return 'Real Energy';
  if (v === 'jfx') return 'JFX';
  if (v === 'dmf') return 'DMF';
  return String(value || '').trim();
}

function monthKeyToRange(monthKey) {
  const raw = String(monthKey || '').trim();
  if (!/^\d{4}-\d{2}$/.test(raw)) return null;
  const [yy, mm] = raw.split('-').map(Number);
  if (!yy || !mm || mm < 1 || mm > 12) return null;
  const start = new Date(Date.UTC(yy, mm - 1, 1));
  const end = new Date(Date.UTC(yy, mm, 1));
  const fmt = (d) => d.toISOString().slice(0, 10);
  return { monthKey: raw, start: fmt(start), end: fmt(end) };
}

async function listBudgetLimits(monthKey, companies = null) {
  const Budget = BudgetLimitModel();
  const range = monthKeyToRange(monthKey);
  if (!range) return [];
  const where = { month_key: range.monthKey };
  if (Array.isArray(companies) && companies.length) {
    where.company = { [Op.in]: companies.map(normalizeCompany).filter(Boolean) };
  }
  const rows = await Budget.findAll({ where });
  return rows.map(r => r.toJSON());
}

async function upsertBudgetLimits(monthKey, budgets, updatedBy = null) {
  const Budget = BudgetLimitModel();
  const range = monthKeyToRange(monthKey);
  if (!range) return 0;
  const items = budgets && typeof budgets === 'object' ? budgets : {};
  let count = 0;
  for (const [companyRaw, valueRaw] of Object.entries(items)) {
    const company = normalizeCompany(companyRaw);
    if (!company) continue;
    const limitValue = Number(valueRaw || 0);
    if (!Number.isFinite(limitValue) || limitValue < 0) continue;
    await Budget.upsert({
      month_key: range.monthKey,
      company,
      limit_value: limitValue,
      updated_by: updatedBy || null,
      updated_at: new Date(),
    });
    count += 1;
  }
  return count;
}

async function getMonthlyReport({ monthKey, companies }) {
  const db = getSequelize();
  const range = monthKeyToRange(monthKey);
  if (!range) {
    return {
      totals_by_company: {},
      grand_total: 0,
      top_cost_centers: [],
      counts: { total: 0, signed: 0, pending: 0 },
    };
  }

  const allowedCompanies = (Array.isArray(companies) ? companies : [])
    .map(normalizeCompany)
    .filter(Boolean);
  const includeNullForDMF = allowedCompanies.includes('DMF');

  const commonWhere = `
    (company = ANY(:companies) OR (:includeNullForDMF = true AND company IS NULL))
  `;

  const parsedDateExpr = `
    CASE
      WHEN data ~ '^\\d{4}-\\d{2}-\\d{2}$' THEN to_date(data, 'YYYY-MM-DD')
      WHEN data ~ '^\\d{2}/\\d{2}/\\d{4}$' THEN to_date(data, 'DD/MM/YYYY')
      WHEN data ~ '^\\d{4}-\\d{2}$' THEN to_date(data || '-01', 'YYYY-MM-DD')
      ELSE NULL
    END
  `;

  const baseCte = `
    WITH scoped AS (
      SELECT
        COALESCE(NULLIF(TRIM(company), ''), 'DMF') AS company_norm,
        NULLIF(TRIM(centro), '') AS centro_norm,
        ABS(COALESCE(valor, 0))::double precision AS valor_abs,
        assinatura,
        ${parsedDateExpr} AS pay_date
      FROM flow_payments
      WHERE ${commonWhere}
    ),
    filtered AS (
      SELECT * FROM scoped
      WHERE pay_date IS NOT NULL
        AND pay_date >= :start::date
        AND pay_date < :end::date
    )
  `;

  const replacements = {
    companies: allowedCompanies,
    includeNullForDMF,
    start: range.start,
    end: range.end,
  };

  const totalsRows = await db.query(
    `${baseCte}
     SELECT company_norm AS company, SUM(valor_abs)::double precision AS total
     FROM filtered
     GROUP BY company_norm
     ORDER BY company_norm ASC`,
    { replacements, type: Sequelize.QueryTypes.SELECT }
  );

  const countsRows = await db.query(
    `${baseCte}
     SELECT
       COUNT(*)::bigint AS total,
       SUM(CASE WHEN assinatura IS NOT NULL THEN 1 ELSE 0 END)::bigint AS signed,
       SUM(CASE WHEN assinatura IS NULL THEN 1 ELSE 0 END)::bigint AS pending
     FROM filtered`,
    { replacements, type: Sequelize.QueryTypes.SELECT }
  );

  const topCentersRows = await db.query(
    `${baseCte}
     SELECT COALESCE(centro_norm, 'Sem centro') AS center, SUM(valor_abs)::double precision AS total
     FROM filtered
     GROUP BY COALESCE(centro_norm, 'Sem centro')
     ORDER BY SUM(valor_abs) DESC
     LIMIT 8`,
    { replacements, type: Sequelize.QueryTypes.SELECT }
  );

  const totalsByCompany = {};
  let grandTotal = 0;
  for (const row of totalsRows || []) {
    const company = normalizeCompany(row.company) || row.company;
    const total = Number(row.total || 0) || 0;
    totalsByCompany[company] = total;
    grandTotal += total;
  }

  const countsRaw = Array.isArray(countsRows) && countsRows[0] ? countsRows[0] : {};
  const counts = {
    total: Number(countsRaw.total || 0) || 0,
    signed: Number(countsRaw.signed || 0) || 0,
    pending: Number(countsRaw.pending || 0) || 0,
  };

  const topCostCenters = (topCentersRows || []).map((r) => ({
    center: String(r.center || 'Sem centro'),
    total: Number(r.total || 0) || 0,
  }));

  return {
    totals_by_company: totalsByCompany,
    grand_total: grandTotal,
    top_cost_centers: topCostCenters,
    counts,
  };
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
    { table: 'app_user_companies', columns: ['user_id', 'company'] }
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
  return { ok: missing.length === 0, missing };
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
  return rows.map(r => r.toJSON());
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
  validateDbSchema,
};
