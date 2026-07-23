// North Admin Panel — Draw SCRIPT (Railway / Postgres / Volume)
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

for (const p of [VOLUME_PATH, path.join(VOLUME_PATH,'exe'), path.join(VOLUME_PATH,'images')]) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway') ? { rejectUnauthorized: false } : false
});

function hashPassword(pw){ return crypto.createHash('sha256').update(pw + SESSION_SECRET).digest('hex'); }
function newToken(){ return crypto.randomBytes(32).toString('hex'); }

async function initDB(){
  // Same schema as keys-dashboard; safe to run on shared DB.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user', created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS keys (
      id TEXT PRIMARY KEY, key TEXT UNIQUE NOT NULL, duration TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'unused', hwid TEXT,
      activated_at TIMESTAMPTZ, expires_at TIMESTAMPTZ,
      created_by TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS logs (
      id TEXT PRIMARY KEY, action TEXT NOT NULL, username TEXT,
      details JSONB, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY, kind TEXT NOT NULL, slot TEXT NOT NULL,
      name TEXT NOT NULL, version TEXT, path TEXT NOT NULL, size BIGINT,
      uploaded_by TEXT, is_current BOOLEAN DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS downloads (
      id TEXT PRIMARY KEY, file_id TEXT, slot TEXT, username TEXT, key_used TEXT,
      ip TEXT, user_agent TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  const { rows } = await pool.query(`SELECT 1 FROM users WHERE username=$1`, [ADMIN_USERNAME]);
  if (!rows.length) {
    await pool.query(`INSERT INTO users (id, username, password, role) VALUES ($1,$2,$3,'dev')`,
      [crypto.randomUUID(), ADMIN_USERNAME, hashPassword(ADMIN_PASSWORD)]);
    console.log('[init] seeded dev user:', ADMIN_USERNAME);
  }
}

// sessions
const sessions = new Map();
function createSession(u){ const t=newToken(); sessions.set(t,{id:u.id,username:u.username,role:u.role,exp:Date.now()+24*3600*1000}); return t; }
function readSession(req){
  const auth = req.headers.authorization || '';
  const t = auth.startsWith('Bearer ') ? auth.slice(7) : (req.query.token || '');
  const s = sessions.get(t); if (!s) return null;
  if (s.exp < Date.now()){ sessions.delete(t); return null; }
  return { ...s, token: t };
}
function requireDev(req,res,next){
  const s = readSession(req);
  if (!s) return res.status(401).json({ error:'unauthorized' });
  if (s.role !== 'dev') return res.status(403).json({ error:'forbidden' });
  req.user = s; next();
}

async function log(action, username, details){
  await pool.query(`INSERT INTO logs (id, action, username, details) VALUES ($1,$2,$3,$4)`,
    [crypto.randomUUID(), action, username || null, details ? JSON.stringify(details) : null]);
}

// multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const kind = req.params.kind === 'image' ? 'images' : 'exe';
    cb(null, path.join(VOLUME_PATH, kind));
  },
  filename: (req, file, cb) => {
    const stamp = Date.now();
    const safe = file.originalname.replace(/[^\w.\-]+/g,'_');
    cb(null, `${stamp}_${safe}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 200 * 1024 * 1024 } }); // 200MB

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ------- auth -------
app.post('/api/login', async (req,res)=>{
  const { username, password } = req.body || {};
  const { rows } = await pool.query(`SELECT * FROM users WHERE username=$1`, [username]);
  const u = rows[0];
  if (!u || u.role !== 'dev' || u.password !== hashPassword(password)) {
    await log('admin_login_failed', username || null, { ip: req.ip });
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  const token = createSession(u);
  await log('admin_login', username, { ip: req.ip });
  res.json({ token, user: { id: u.id, username: u.username, role: u.role } });
});
app.post('/api/logout', (req,res)=>{ const s=readSession(req); if(s) sessions.delete(s.token); res.json({ok:true}); });
app.get('/api/me', requireDev, (req,res)=> res.json({ user: req.user }));

// ------- admins mgmt -------
app.get('/api/admins', requireDev, async (req,res)=>{
  const { rows } = await pool.query(`SELECT id, username, role, created_at FROM users WHERE role='dev' ORDER BY created_at DESC`);
  res.json({ admins: rows });
});
app.post('/api/admins', requireDev, async (req,res)=>{
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error:'missing_fields' });
  const exists = await pool.query(`SELECT 1 FROM users WHERE username=$1`, [username]);
  if (exists.rows.length) return res.status(409).json({ error:'exists' });
  await pool.query(`INSERT INTO users (id, username, password, role) VALUES ($1,$2,$3,'dev')`,
    [crypto.randomUUID(), username, hashPassword(password)]);
  await log('admin_created', req.user.username, { new: username });
  res.json({ ok:true });
});
app.delete('/api/admins/:id', requireDev, async (req,res)=>{
  const { rows } = await pool.query(`SELECT username FROM users WHERE id=$1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error:'not_found' });
  if (rows[0].username === ADMIN_USERNAME) return res.status(400).json({ error:'cannot_remove_primary' });
  await pool.query(`DELETE FROM users WHERE id=$1 AND role='dev'`, [req.params.id]);
  await log('admin_deleted', req.user.username, { removed: rows[0].username });
  res.json({ ok:true });
});

// ------- files: upload / list / activate / delete -------
app.post('/api/files/:kind/:slot', requireDev, upload.single('file'), async (req,res)=>{
  const { kind, slot } = req.params;
  if (!['exe','image'].includes(kind)) return res.status(400).json({ error:'bad_kind' });
  if (!req.file) return res.status(400).json({ error:'no_file' });
  const version = (req.body && req.body.version) || `v${Date.now()}`;
  const id = crypto.randomUUID();
  await pool.query(`UPDATE files SET is_current=FALSE WHERE kind=$1 AND slot=$2`, [kind, slot]);
  await pool.query(
    `INSERT INTO files (id, kind, slot, name, version, path, size, uploaded_by, is_current)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,TRUE)`,
    [id, kind, slot, req.file.originalname, version, req.file.path, req.file.size, req.user.username]
  );
  await log('file_uploaded', req.user.username, { kind, slot, name: req.file.originalname, version });
  res.json({ ok:true, id, version });
});
app.get('/api/files/:kind/:slot?', requireDev, async (req,res)=>{
  const { kind, slot } = req.params;
  const params = [kind];
  let where = `kind=$1`;
  if (slot){ params.push(slot); where += ` AND slot=$${params.length}`; }
  const { rows } = await pool.query(`SELECT id, kind, slot, name, version, size, uploaded_by, is_current, created_at FROM files WHERE ${where} ORDER BY created_at DESC LIMIT 200`, params);
  res.json({ files: rows });
});
app.post('/api/files/:id/activate', requireDev, async (req,res)=>{
  const { rows } = await pool.query(`SELECT kind, slot FROM files WHERE id=$1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error:'not_found' });
  await pool.query(`UPDATE files SET is_current=FALSE WHERE kind=$1 AND slot=$2`, [rows[0].kind, rows[0].slot]);
  await pool.query(`UPDATE files SET is_current=TRUE WHERE id=$1`, [req.params.id]);
  await log('file_activated', req.user.username, { id: req.params.id });
  res.json({ ok:true });
});
app.delete('/api/files/:id', requireDev, async (req,res)=>{
  const { rows } = await pool.query(`SELECT path FROM files WHERE id=$1`, [req.params.id]);
  if (rows[0] && fs.existsSync(rows[0].path)) { try { fs.unlinkSync(rows[0].path); } catch(e){} }
  await pool.query(`DELETE FROM files WHERE id=$1`, [req.params.id]);
  await log('file_deleted', req.user.username, { id: req.params.id });
  res.json({ ok:true });
});

// ------- analytics -------
app.get('/api/stats', requireDev, async (req,res)=>{
  const [dl, byDay, topUsers, topFiles, keysCount, activeKeys, admins] = await Promise.all([
    pool.query(`SELECT COUNT(*)::int c FROM downloads`),
    pool.query(`SELECT to_char(created_at::date,'YYYY-MM-DD') d, COUNT(*)::int c FROM downloads WHERE created_at > NOW() - INTERVAL '30 days' GROUP BY 1 ORDER BY 1`),
    pool.query(`SELECT COALESCE(username,'ضيف') u, COUNT(*)::int c FROM downloads GROUP BY 1 ORDER BY c DESC LIMIT 10`),
    pool.query(`SELECT slot, COUNT(*)::int c FROM downloads GROUP BY slot ORDER BY c DESC`),
    pool.query(`SELECT COUNT(*)::int c FROM keys`),
    pool.query(`SELECT COUNT(*)::int c FROM keys WHERE status='active' AND (expires_at IS NULL OR expires_at > NOW())`),
    pool.query(`SELECT COUNT(*)::int c FROM users WHERE role='dev'`)
  ]);
  res.json({
    downloads_total: dl.rows[0].c,
    downloads_by_day: byDay.rows,
    top_users: topUsers.rows,
    top_files: topFiles.rows,
    keys_total: keysCount.rows[0].c,
    keys_active: activeKeys.rows[0].c,
    admins_count: admins.rows[0].c
  });
});
app.get('/api/downloads', requireDev, async (req,res)=>{
  const { rows } = await pool.query(`SELECT id, slot, username, ip, user_agent, created_at FROM downloads ORDER BY created_at DESC LIMIT 300`);
  res.json({ downloads: rows });
});
app.get('/api/logs', requireDev, async (req,res)=>{
  const { rows } = await pool.query(`SELECT id, action, username, details, created_at FROM logs ORDER BY created_at DESC LIMIT 300`);
  res.json({ logs: rows });
});

app.get('/api/health', (req,res)=> res.json({ ok:true }));
app.get('*', (req,res)=> res.sendFile(path.join(__dirname,'public','index.html')));

initDB().then(()=> app.listen(PORT, ()=> console.log(`[admin-panel] listening on :${PORT}`)))
  .catch(e=>{ console.error('DB init failed', e); process.exit(1); });
