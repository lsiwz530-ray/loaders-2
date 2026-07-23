// North Admin Panel — Draw SCRIPT
// Public loaders storefront + Admin dashboard (Railway / Postgres / Volume)

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const { Pool } = require('pg');

const PORT = process.env.PORT || 8080;
const VOLUME_PATH = process.env.VOLUME_PATH || '/data';
const SESSION_SECRET = process.env.SESSION_SECRET || 'draw_dev_secret_change_me';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'North';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'North123';

for (const p of [VOLUME_PATH, path.join(VOLUME_PATH, 'exe'), path.join(VOLUME_PATH, 'images')]) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && /railway|render|supabase|amazonaws/i.test(process.env.DATABASE_URL)
    ? { rejectUnauthorized: false } : false
});

// -------- utils --------
function hashPassword(pw) { return crypto.createHash('sha256').update(pw + SESSION_SECRET).digest('hex'); }
function hashPasswordDraw(pw) { return crypto.createHash('sha256').update(pw + 'DRAW_SALT_2024').digest('hex'); }
function newToken() { return crypto.randomBytes(32).toString('hex'); }

// -------- schema --------
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS keys (
      id TEXT PRIMARY KEY,
      key TEXT UNIQUE NOT NULL,
      duration TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'unused',
      hwid TEXT,
      activated_at TIMESTAMPTZ,
      expires_at TIMESTAMPTZ,
      created_by TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS logs (
      id TEXT PRIMARY KEY,
      action TEXT NOT NULL,
      username TEXT,
      details JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      slot TEXT NOT NULL DEFAULT 'generic',
      name TEXT NOT NULL,
      version TEXT,
      path TEXT NOT NULL,
      size BIGINT,
      uploaded_by TEXT,
      is_current BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS downloads (
      id TEXT PRIMARY KEY,
      loader_id TEXT,
      file_id TEXT,
      slot TEXT,
      username TEXT,
      key_used TEXT,
      ip TEXT,
      user_agent TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS loaders (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      tutorial_text TEXT DEFAULT '',
      tutorial_video TEXT DEFAULT '',
      version TEXT DEFAULT '',
      image_file_id TEXT,
      exe_file_id TEXT,
      sort_order INT DEFAULT 100,
      visible BOOLEAN DEFAULT TRUE,
      require_key BOOLEAN DEFAULT TRUE,
      download_count INT DEFAULT 0,
      created_by TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_loaders_sort ON loaders(sort_order, created_at);
    CREATE INDEX IF NOT EXISTS idx_downloads_loader ON downloads(loader_id);
  `);

  // seed primary admin (support both hash formats — try DRAW_SALT_2024 too for legacy dash compatibility)
  const { rows } = await pool.query(`SELECT id, password FROM users WHERE username=$1`, [ADMIN_USERNAME]);
  if (!rows.length) {
    await pool.query(`INSERT INTO users (id, username, password, role) VALUES ($1,$2,$3,'dev')`,
      [crypto.randomUUID(), ADMIN_USERNAME, hashPassword(ADMIN_PASSWORD)]);
    console.log('[init] seeded dev user:', ADMIN_USERNAME);
  }
}

// -------- sessions --------
const sessions = new Map();
function createSession(u) {
  const t = newToken();
  sessions.set(t, { id: u.id, username: u.username, role: u.role, exp: Date.now() + 24 * 3600 * 1000 });
  return t;
}
function readSession(req) {
  const auth = req.headers.authorization || '';
  const t = auth.startsWith('Bearer ') ? auth.slice(7) : (req.query.token || '');
  const s = sessions.get(t);
  if (!s) return null;
  if (s.exp < Date.now()) { sessions.delete(t); return null; }
  return { ...s, token: t };
}
function requireDev(req, res, next) {
  const s = readSession(req);
  if (!s) return res.status(401).json({ error: 'unauthorized' });
  if (s.role !== 'dev') return res.status(403).json({ error: 'forbidden' });
  req.user = s;
  next();
}

async function log(action, username, details) {
  try {
    await pool.query(`INSERT INTO logs (id, action, username, details) VALUES ($1,$2,$3,$4)`,
      [crypto.randomUUID(), action, username || null, details ? JSON.stringify(details) : null]);
  } catch (e) { console.error('[log]', e.message); }
}

// -------- multer (uploads) --------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const kind = req.params.kind === 'image' ? 'images' : 'exe';
    cb(null, path.join(VOLUME_PATH, kind));
  },
  filename: (req, file, cb) => {
    const stamp = Date.now();
    const safe = file.originalname.replace(/[^\w.\-]+/g, '_');
    cb(null, `${stamp}_${safe}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 500 * 1024 * 1024 } }); // 500MB

// -------- app --------
const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '4mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ================= AUTH =================
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing' });
  const { rows } = await pool.query(`SELECT * FROM users WHERE username=$1`, [username]);
  const u = rows[0];
  if (!u || u.role !== 'dev') {
    await log('admin_login_failed', username, { ip: req.ip });
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  // support new hash and legacy dash hash
  const ok = u.password === hashPassword(password) || u.password === hashPasswordDraw(password);
  if (!ok) {
    await log('admin_login_failed', username, { ip: req.ip });
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  const token = createSession(u);
  await log('admin_login', username, { ip: req.ip });
  res.json({ token, user: { id: u.id, username: u.username, role: u.role } });
});
app.post('/api/logout', (req, res) => {
  const s = readSession(req);
  if (s) sessions.delete(s.token);
  res.json({ ok: true });
});
app.get('/api/me', requireDev, (req, res) => res.json({ user: req.user }));

// ================= ADMINS (TEAM) =================
app.get('/api/admins', requireDev, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, username, role, created_at FROM users WHERE role='dev' ORDER BY created_at ASC`
  );
  res.json({ admins: rows });
});
app.post('/api/admins', requireDev, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing_fields' });
  if (String(password).length < 4) return res.status(400).json({ error: 'weak_password' });
  const exists = await pool.query(`SELECT 1 FROM users WHERE username=$1`, [username]);
  if (exists.rows.length) return res.status(409).json({ error: 'exists' });
  await pool.query(`INSERT INTO users (id, username, password, role) VALUES ($1,$2,$3,'dev')`,
    [crypto.randomUUID(), username, hashPassword(password)]);
  await log('admin_created', req.user.username, { new: username });
  res.json({ ok: true });
});
app.post('/api/admins/:id/password', requireDev, async (req, res) => {
  const { password } = req.body || {};
  if (!password || String(password).length < 4) return res.status(400).json({ error: 'weak_password' });
  const { rowCount } = await pool.query(`UPDATE users SET password=$1 WHERE id=$2 AND role='dev'`,
    [hashPassword(password), req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
  await log('admin_password_changed', req.user.username, { id: req.params.id });
  res.json({ ok: true });
});
app.delete('/api/admins/:id', requireDev, async (req, res) => {
  const { rows } = await pool.query(`SELECT username FROM users WHERE id=$1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  if (rows[0].username === ADMIN_USERNAME) return res.status(400).json({ error: 'cannot_remove_primary' });
  await pool.query(`DELETE FROM users WHERE id=$1 AND role='dev'`, [req.params.id]);
  await log('admin_deleted', req.user.username, { removed: rows[0].username });
  res.json({ ok: true });
});

// ================= FILES (raw upload/list/delete) =================
app.post('/api/files/:kind/:slot?', requireDev, upload.single('file'), async (req, res) => {
  const { kind } = req.params;
  const slot = req.params.slot || 'generic';
  if (!['exe', 'image'].includes(kind)) return res.status(400).json({ error: 'bad_kind' });
  if (!req.file) return res.status(400).json({ error: 'no_file' });
  const version = (req.body && req.body.version) || `v${Date.now()}`;
  const id = crypto.randomUUID();
  await pool.query(
    `INSERT INTO files (id, kind, slot, name, version, path, size, uploaded_by, is_current)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,TRUE)`,
    [id, kind, slot, req.file.originalname, version, req.file.path, req.file.size, req.user.username]
  );
  await log('file_uploaded', req.user.username, { kind, slot, name: req.file.originalname, size: req.file.size });
  res.json({ ok: true, id, name: req.file.originalname, size: req.file.size, version });
});
app.get('/api/files/:kind', requireDev, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, kind, slot, name, version, size, uploaded_by, created_at
     FROM files WHERE kind=$1 ORDER BY created_at DESC LIMIT 500`, [req.params.kind]
  );
  res.json({ files: rows });
});
app.delete('/api/files/:id', requireDev, async (req, res) => {
  const { rows } = await pool.query(`SELECT path FROM files WHERE id=$1`, [req.params.id]);
  if (rows[0] && fs.existsSync(rows[0].path)) { try { fs.unlinkSync(rows[0].path); } catch(e){} }
  await pool.query(`DELETE FROM files WHERE id=$1`, [req.params.id]);
  await log('file_deleted', req.user.username, { id: req.params.id });
  res.json({ ok: true });
});

// ================= LOADERS (CRUD) =================
app.get('/api/loaders', requireDev, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT l.*,
      fi.name AS image_name, fi.path AS image_path,
      fe.name AS exe_name, fe.size AS exe_size, fe.version AS exe_version, fe.created_at AS exe_uploaded_at
    FROM loaders l
    LEFT JOIN files fi ON fi.id = l.image_file_id
    LEFT JOIN files fe ON fe.id = l.exe_file_id
    ORDER BY l.sort_order ASC, l.created_at ASC
  `);
  res.json({ loaders: rows });
});
app.post('/api/loaders', requireDev, async (req, res) => {
  const { name, description = '', tutorial_text = '', tutorial_video = '', version = '',
          image_file_id = null, exe_file_id = null, visible = true, require_key = true } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name_required' });
  const id = crypto.randomUUID();
  // put new loader at the end
  const { rows: mx } = await pool.query(`SELECT COALESCE(MAX(sort_order),0)+10 AS n FROM loaders`);
  const sort_order = mx[0].n;
  await pool.query(
    `INSERT INTO loaders (id, name, description, tutorial_text, tutorial_video, version, image_file_id, exe_file_id, visible, require_key, sort_order, created_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [id, name, description, tutorial_text, tutorial_video, version, image_file_id, exe_file_id, !!visible, !!require_key, sort_order, req.user.username]
  );
  await log('loader_created', req.user.username, { id, name });
  res.json({ ok: true, id });
});
app.patch('/api/loaders/:id', requireDev, async (req, res) => {
  const fields = ['name','description','tutorial_text','tutorial_video','version','image_file_id','exe_file_id','visible','require_key','sort_order'];
  const sets = [], vals = [];
  for (const f of fields) {
    if (req.body && Object.prototype.hasOwnProperty.call(req.body, f)) {
      vals.push(req.body[f]);
      sets.push(`${f}=$${vals.length}`);
    }
  }
  if (!sets.length) return res.json({ ok: true });
  vals.push(req.params.id);
  await pool.query(`UPDATE loaders SET ${sets.join(', ')}, updated_at=NOW() WHERE id=$${vals.length}`, vals);
  await log('loader_updated', req.user.username, { id: req.params.id, keys: Object.keys(req.body || {}) });
  res.json({ ok: true });
});
app.post('/api/loaders/reorder', requireDev, async (req, res) => {
  const { order } = req.body || {};
  if (!Array.isArray(order)) return res.status(400).json({ error: 'bad_order' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (let i = 0; i < order.length; i++) {
      await client.query(`UPDATE loaders SET sort_order=$1 WHERE id=$2`, [(i + 1) * 10, order[i]]);
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    return res.status(500).json({ error: 'reorder_failed' });
  } finally { client.release(); }
  res.json({ ok: true });
});
app.delete('/api/loaders/:id', requireDev, async (req, res) => {
  await pool.query(`DELETE FROM loaders WHERE id=$1`, [req.params.id]);
  await log('loader_deleted', req.user.username, { id: req.params.id });
  res.json({ ok: true });
});

// ================= PUBLIC (customer-facing) =================
// list visible loaders (no auth)
app.get('/api/public/loaders', async (req, res) => {
  const { rows } = await pool.query(`
    SELECT
      l.id, l.name, l.description, l.tutorial_text, l.tutorial_video,
      l.version, l.download_count, l.require_key, l.updated_at,
      CASE WHEN l.image_file_id IS NOT NULL THEN true ELSE false END AS has_image,
      CASE WHEN l.exe_file_id  IS NOT NULL THEN true ELSE false END AS has_exe,
      fe.name AS exe_name, fe.size AS exe_size, fe.created_at AS exe_uploaded_at
    FROM loaders l
    LEFT JOIN files fe ON fe.id = l.exe_file_id
    WHERE l.visible = TRUE
    ORDER BY l.sort_order ASC, l.created_at ASC
  `);
  res.json({ loaders: rows });
});

// serve loader image publicly
app.get('/api/public/loaders/:id/image', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT f.path, f.name FROM loaders l JOIN files f ON f.id = l.image_file_id
     WHERE l.id=$1 AND l.visible=TRUE`, [req.params.id]);
  if (!rows[0] || !fs.existsSync(rows[0].path)) return res.status(404).end();
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.sendFile(path.resolve(rows[0].path));
});

// check a key — never sets hwid, never activates
app.post('/api/public/keys/check', async (req, res) => {
  const { key } = req.body || {};
  if (!key) return res.status(400).json({ ok: false, reason: 'missing_key' });
  const { rows } = await pool.query(`SELECT * FROM keys WHERE key=$1`, [String(key).trim()]);
  const k = rows[0];
  if (!k) return res.json({ ok: false, reason: 'not_found' });
  if (k.status === 'banned') return res.json({ ok: false, reason: 'banned' });
  const activated = !!k.activated_at;
  const now = Date.now();
  let remaining_ms = null, expired = false;
  if (activated && k.expires_at) {
    remaining_ms = new Date(k.expires_at).getTime() - now;
    if (remaining_ms <= 0) expired = true;
  }
  res.json({
    ok: !expired,
    activated,
    expired,
    duration: k.duration,
    remaining_ms,
    // helpful hint for the UI
    hint: !activated ? 'pending_first_activation' : (expired ? 'expired' : 'active')
  });
});

// download an exe: requires valid (not expired, not banned) key when require_key=true.
// Does NOT touch hwid. Does NOT activate. Only counts + logs.
app.get('/api/public/loaders/:id/download', async (req, res) => {
  const { key } = req.query;
  const { rows: lrows } = await pool.query(`
    SELECT l.*, f.path AS exe_path, f.name AS exe_name
    FROM loaders l LEFT JOIN files f ON f.id = l.exe_file_id
    WHERE l.id=$1 AND l.visible=TRUE`, [req.params.id]);
  const l = lrows[0];
  if (!l) return res.status(404).json({ error: 'not_found' });
  if (!l.exe_path || !fs.existsSync(l.exe_path)) return res.status(404).json({ error: 'exe_missing' });

  let keyUsed = null;
  if (l.require_key) {
    if (!key) return res.status(400).json({ error: 'key_required' });
    const { rows: krows } = await pool.query(`SELECT * FROM keys WHERE key=$1`, [String(key).trim()]);
    const k = krows[0];
    if (!k) return res.status(403).json({ error: 'invalid_key' });
    if (k.status === 'banned') return res.status(403).json({ error: 'banned_key' });
    if (k.activated_at && k.expires_at && new Date(k.expires_at).getTime() < Date.now()) {
      return res.status(403).json({ error: 'expired_key' });
    }
    keyUsed = k.key;
  }

  await pool.query(`UPDATE loaders SET download_count = download_count + 1 WHERE id=$1`, [l.id]);
  await pool.query(
    `INSERT INTO downloads (id, loader_id, file_id, slot, key_used, ip, user_agent)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [crypto.randomUUID(), l.id, l.exe_file_id, l.name, keyUsed,
     req.headers['x-forwarded-for'] || req.ip, req.headers['user-agent'] || null]
  );

  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(l.exe_name || (l.name + '.exe'))}"`);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.sendFile(path.resolve(l.exe_path));
});

// ================= ANALYTICS =================
app.get('/api/stats', requireDev, async (req, res) => {
  const [dl, byDay, topLoaders, keysCount, activeKeys, admins, loadersCount, visibleLoaders] = await Promise.all([
    pool.query(`SELECT COUNT(*)::int c FROM downloads`),
    pool.query(`SELECT to_char(created_at::date,'YYYY-MM-DD') d, COUNT(*)::int c FROM downloads
                WHERE created_at > NOW() - INTERVAL '30 days' GROUP BY 1 ORDER BY 1`),
    pool.query(`SELECT l.name, l.download_count::int c FROM loaders l ORDER BY l.download_count DESC LIMIT 10`),
    pool.query(`SELECT COUNT(*)::int c FROM keys`),
    pool.query(`SELECT COUNT(*)::int c FROM keys WHERE (status='active' OR status='unused')
                AND (expires_at IS NULL OR expires_at > NOW())`),
    pool.query(`SELECT COUNT(*)::int c FROM users WHERE role='dev'`),
    pool.query(`SELECT COUNT(*)::int c FROM loaders`),
    pool.query(`SELECT COUNT(*)::int c FROM loaders WHERE visible=TRUE`)
  ]);
  res.json({
    downloads_total: dl.rows[0].c,
    downloads_by_day: byDay.rows,
    top_loaders: topLoaders.rows,
    keys_total: keysCount.rows[0].c,
    keys_active: activeKeys.rows[0].c,
    admins_count: admins.rows[0].c,
    loaders_total: loadersCount.rows[0].c,
    loaders_visible: visibleLoaders.rows[0].c
  });
});
app.get('/api/downloads', requireDev, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT d.id, d.slot, d.key_used, d.ip, d.user_agent, d.created_at,
           l.name AS loader_name
    FROM downloads d LEFT JOIN loaders l ON l.id = d.loader_id
    ORDER BY d.created_at DESC LIMIT 500
  `);
  res.json({ downloads: rows });
});
app.get('/api/logs', requireDev, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, action, username, details, created_at FROM logs ORDER BY created_at DESC LIMIT 500`
  );
  res.json({ logs: rows });
});

// ================= HEALTH + SPA =================
app.get('/api/health', (req, res) => res.json({ ok: true }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

initDB()
  .then(() => app.listen(PORT, () => console.log(`[north-loaders] listening on :${PORT}`)))
  .catch(e => { console.error('DB init failed', e); process.exit(1); });
