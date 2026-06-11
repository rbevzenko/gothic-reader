/**
 * Gothic Reader — Express backend
 *
 * Storage: SQLite via better-sqlite3
 * Secrets: .env (see .env.example)
 *
 * Endpoints:
 *   POST /api/auth/register    — register with email + password
 *   POST /api/auth/login       — login, returns session token
 *   POST /api/auth/logout      — invalidate session
 *   GET  /api/auth/me          — current user info + balance + history
 *   POST /api/claude           — proxy Claude call, deduct 1 credit
 *   GET  /api/credits?uid=…    — return credit balance (legacy)
 *   POST /api/checkout         — create Stripe Checkout session
 *   POST /api/stripe-webhook   — Stripe webhook → top-up credits
 *   POST /api/checkout-ru      — create YooKassa payment
 *   POST /api/yookassa-webhook — YooKassa webhook → top-up credits
 *   GET  /admin                — admin panel (HTTP Basic Auth)
 *   GET  /admin/api/*          — admin API
 *   GET  /account              — user account page
 *   GET  /*                    — serve index.html
 */

import express from 'express';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import path from 'path';
import { jsonrepair } from 'jsonrepair';
import fs from 'fs';
import os from 'os';
import { fileURLToPath } from 'url';
import 'dotenv/config';
import multer from 'multer';
import { execFile } from 'child_process';
import { promisify } from 'util';
const execFileAsync = promisify(execFile);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// ── Model pricing (per 1M tokens, USD) ───────────────────────────────────────

const MODEL_PRICING = {
  'claude-haiku-4-5-20251001': { input: 1.00,  output: 5.00  },
  'claude-sonnet-4-6':         { input: 3.00,  output: 15.00 },
  'claude-opus-4-8':           { input: 15.00, output: 75.00 },
};

function calcCost(model, inputTokens, outputTokens) {
  const p = MODEL_PRICING[model] || { input: 3.00, output: 15.00 };
  return (inputTokens / 1e6) * p.input + (outputTokens / 1e6) * p.output;
}

// ── Database ──────────────────────────────────────────────────────────────────

const db = new Database(process.env.DB_PATH || 'credits.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS credits (
    uid          TEXT PRIMARY KEY,
    balance      INTEGER NOT NULL DEFAULT 0,
    total_bought INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    email        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT   NOT NULL,
    uid          TEXT    NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT    PRIMARY KEY,
    uid        TEXT    NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS projects (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    uid          TEXT    NOT NULL,
    name         TEXT    NOT NULL,
    filename     TEXT    NOT NULL DEFAULT '',
    total_pages  INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at   INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS project_pages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    page_num    INTEGER NOT NULL,
    result_json TEXT    NOT NULL,
    model       TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE(project_id, page_num)
  );

  CREATE INDEX IF NOT EXISTS idx_projects_uid ON projects(uid);
  CREATE INDEX IF NOT EXISTS idx_project_pages_pid ON project_pages(project_id);

  CREATE TABLE IF NOT EXISTS requests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    uid           TEXT    NOT NULL,
    model         TEXT    NOT NULL,
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd      REAL    NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS payments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    uid         TEXT    NOT NULL,
    package_id  TEXT    NOT NULL,
    credits     INTEGER NOT NULL,
    amount_eur  REAL    NOT NULL,
    stripe_id   TEXT,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    uid         TEXT    NOT NULL,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    pages       TEXT    NOT NULL,
    mode        TEXT    NOT NULL DEFAULT 'modernize',
    lang        TEXT    NOT NULL DEFAULT 'русский',
    model       TEXT    NOT NULL DEFAULT 'claude-haiku-4-5-20251001',
    latin       INTEGER NOT NULL DEFAULT 0,
    status      TEXT    NOT NULL DEFAULT 'pending',
    pages_done  INTEGER NOT NULL DEFAULT 0,
    pages_total INTEGER NOT NULL DEFAULT 0,
    pdf_path    TEXT,
    error       TEXT,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at  INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE INDEX IF NOT EXISTS idx_requests_uid ON requests(uid);
  CREATE INDEX IF NOT EXISTS idx_requests_ts  ON requests(created_at);
  CREATE INDEX IF NOT EXISTS idx_payments_uid ON payments(uid);
  CREATE INDEX IF NOT EXISTS idx_payments_ts  ON payments(created_at);
  CREATE INDEX IF NOT EXISTS idx_sessions_uid ON sessions(uid);
  CREATE INDEX IF NOT EXISTS idx_jobs_uid     ON jobs(uid);
  CREATE INDEX IF NOT EXISTS idx_jobs_status  ON jobs(status);

  CREATE TABLE IF NOT EXISTS job_page_images (
    job_id     INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    page_num   INTEGER NOT NULL,
    image_data TEXT    NOT NULL,
    PRIMARY KEY (job_id, page_num)
  );
`);

// Prepared statements — credits
const stmtGetCredits    = db.prepare(`SELECT balance, total_bought, created_at FROM credits WHERE uid = ?`);
const stmtUpsertCredits = db.prepare(`
  INSERT INTO credits (uid, balance, total_bought) VALUES (?, ?, ?)
  ON CONFLICT(uid) DO UPDATE SET balance = excluded.balance, total_bought = excluded.total_bought
`);
const stmtLogRequest = db.prepare(`
  INSERT INTO requests (uid, model, input_tokens, output_tokens, cost_usd) VALUES (?, ?, ?, ?, ?)
`);
const stmtLogPayment = db.prepare(`
  INSERT INTO payments (uid, package_id, credits, amount_eur, stripe_id) VALUES (?, ?, ?, ?, ?)
`);
const stmtGetSetting = db.prepare(`SELECT value FROM settings WHERE key = ?`);
const stmtSetSetting = db.prepare(`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`);

// Prepared statements — auth
const stmtCreateUser   = db.prepare(`INSERT INTO users (email, password_hash, uid) VALUES (?, ?, ?)`);
const stmtGetUserEmail = db.prepare(`SELECT * FROM users WHERE email = ?`);
const stmtGetUserUid   = db.prepare(`SELECT * FROM users WHERE uid = ?`);
const stmtCreateSession = db.prepare(`INSERT INTO sessions (token, uid, expires_at) VALUES (?, ?, ?)`);
const stmtGetSession    = db.prepare(`SELECT * FROM sessions WHERE token = ? AND expires_at > unixepoch()`);
const stmtDeleteSession = db.prepare(`DELETE FROM sessions WHERE token = ?`);
const stmtCleanSessions = db.prepare(`DELETE FROM sessions WHERE expires_at <= unixepoch()`);

// Clean expired sessions on startup
stmtCleanSessions.run();

function fetchBalance(uid) {
  return stmtGetCredits.get(uid)?.balance ?? 0;
}
function fetchUser(uid) {
  return stmtGetCredits.get(uid) || { balance: 0, total_bought: 0, created_at: null };
}
function saveBalance(uid, balance, totalBought) {
  const cur = stmtGetCredits.get(uid);
  stmtUpsertCredits.run(uid, balance, totalBought ?? cur?.total_bought ?? 0);
}
function getSetting(key, def = null) {
  return stmtGetSetting.get(key)?.value ?? def;
}

function createSessionToken(uid) {
  const token     = crypto.randomBytes(32).toString('hex');
  const expiresAt = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30; // 30 days
  stmtCreateSession.run(token, uid, expiresAt);
  return token;
}

function getUidFromRequest(req) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) {
    const session = stmtGetSession.get(auth.slice(7));
    if (session) return session.uid;
  }
  return req.headers['x-user-id'] || null;
}

// ── Package config (can be overridden via admin settings) ────────────────────

function getPackages() {
  try {
    const s = getSetting('packages');
    if (s) return JSON.parse(s);
  } catch {}
  return {
    pages_100:  { credits: 100,  amount_eur: 5.00,  amount_rub: 490,  price_id: process.env.STRIPE_PRICE_100  || '' },
    pages_500:  { credits: 500,  amount_eur: 15.00, amount_rub: 1490, price_id: process.env.STRIPE_PRICE_500  || '' },
    pages_1000: { credits: 1000, amount_eur: 25.00, amount_rub: 2490, price_id: process.env.STRIPE_PRICE_1000 || '' },
  };
}

// ── Middleware ────────────────────────────────────────────────────────────────

app.use((req, res, next) => {
  res.set({
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-User-Id',
  });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.post('/api/stripe-webhook',   express.raw({ type: 'application/json' }), handleWebhook);
app.post('/api/yookassa-webhook', express.json(), handleYooKassaWebhook);
app.use(express.json({ limit: '20mb' }));

// ── Admin auth middleware ─────────────────────────────────────────────────────

function adminAuth(req, res, next) {
  const login    = process.env.ADMIN_LOGIN    || 'admin';
  const password = process.env.ADMIN_PASSWORD || 'changeme';
  const auth = req.headers.authorization || '';
  const [type, cred] = auth.split(' ');
  if (type === 'Basic') {
    const [u, p] = Buffer.from(cred, 'base64').toString().split(':');
    if (u === login && p === password) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="Admin"');
  res.status(401).send('Unauthorized');
}

// ── Public API routes ─────────────────────────────────────────────────────────

app.post('/api/auth/register', handleRegister);
app.post('/api/auth/login',    handleLogin);
app.post('/api/auth/logout',          handleLogout);
app.get('/api/auth/me',              handleMe);
app.post('/api/auth/change-password', handleChangePassword);

app.post('/api/claude',        handleClaude);
app.post('/api/process-url',   handleProcessUrl);
app.get('/api/proxy-image',    handleProxyImage);
app.get('/api/credits',        handleCredits);
app.post('/api/checkout',      handleCheckout);
app.post('/api/checkout-ru',   handleCheckoutRu);

// Projects
app.get('/api/projects',                    requireAuth, listProjects);
app.post('/api/projects',                   requireAuth, createProject);
app.get('/api/projects/:id',                requireAuth, getProject);
app.delete('/api/projects/:id',             requireAuth, deleteProject);
app.put('/api/projects/:id',                requireAuth, updateProject);
app.post('/api/projects/:id/pages',         requireAuth, saveProjectPage);
app.get('/api/projects/:id/pages',          requireAuth, getProjectPages);
app.delete('/api/projects/:id/pages/:num',  requireAuth, deleteProjectPage);

// Jobs (server-side processing queue)
const upload = multer({ dest: os.tmpdir(), limits: { fileSize: 100 * 1024 * 1024 } });
app.post('/api/jobs',           requireAuth, upload.single('pdf'), createJob);
app.get('/api/jobs/:id',        requireAuth, getJob);
app.delete('/api/jobs/:id',     requireAuth, cancelJob);

// ── Admin routes ──────────────────────────────────────────────────────────────

app.get('/admin',              adminAuth, serveAdmin);
app.get('/admin/api/stats',    adminAuth, adminStats);
app.get('/admin/api/users',    adminAuth, adminUsers);
app.get('/admin/api/payments', adminAuth, adminPayments);
app.get('/admin/api/requests', adminAuth, adminRequests);
app.post('/admin/api/credits', adminAuth, adminSetCredits);
app.get('/admin/api/settings', adminAuth, adminGetSettings);
app.post('/admin/api/settings',adminAuth, adminSaveSettings);

// Account page
app.get('/account', (req, res) => res.sendFile(path.join(__dirname, 'account.html')));
app.get('/about',   (req, res) => res.sendFile(path.join(__dirname, 'about.html')));

// Frontend
app.use(express.static(__dirname));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ── Auth middleware ───────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  const uid = getUidFromRequest(req);
  if (!uid) return res.status(401).json({ error: 'Not authenticated' });
  req.uid = uid;
  next();
}

// ── Auth handlers ─────────────────────────────────────────────────────────────

async function handleRegister(req, res) {
  const { email, password, uid: anonUid } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const existing = stmtGetUserEmail.get(email);
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  // Use existing anonymous uid (preserves credits) or create new one
  // But only if uid is not already registered to another user
  const uidTaken = anonUid ? stmtGetUserUid.get(anonUid) : null;
  const uid = (!uidTaken && anonUid) ? anonUid : crypto.randomUUID();
  const hash = await bcrypt.hash(password, 10);

  try {
    stmtCreateUser.run(email, hash, uid);
    // Ensure credits row exists
    if (!stmtGetCredits.get(uid)) stmtUpsertCredits.run(uid, 0, 0);

    // Promo: first 100 users get 10 free pages
    const PROMO_LIMIT = 100;
    const PROMO_CREDITS = 10;
    const promoSetting = getSetting('promo_enabled', '1');
    if (promoSetting === '1') {
      const promoCount = db.prepare(`SELECT COUNT(*) as n FROM users`).get().n;
      if (promoCount <= PROMO_LIMIT) {
        const cur = stmtGetCredits.get(uid);
        saveBalance(uid, (cur?.balance || 0) + PROMO_CREDITS);
        console.log(`[promo] ${email} got ${PROMO_CREDITS} free pages (user #${promoCount}/${PROMO_LIMIT})`);
      }
    }

    const token = createSessionToken(uid);
    res.json({ token, uid, email });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

async function handleLogin(req, res) {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = stmtGetUserEmail.get(email);
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

  const token = createSessionToken(user.uid);
  res.json({ token, uid: user.uid, email: user.email });
}

function handleLogout(req, res) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) stmtDeleteSession.run(auth.slice(7));
  res.json({ ok: true });
}

function handleMe(req, res) {
  const uid = getUidFromRequest(req);
  if (!uid) return res.status(401).json({ error: 'Not authenticated' });

  const credits = fetchUser(uid);
  const user    = stmtGetUserUid.get(uid);

  const recentRequests = db.prepare(`
    SELECT model, input_tokens, output_tokens, cost_usd, created_at
    FROM requests WHERE uid = ? ORDER BY created_at DESC LIMIT 20
  `).all(uid);

  const recentPayments = db.prepare(`
    SELECT package_id, credits, amount_eur, created_at
    FROM payments WHERE uid = ? ORDER BY created_at DESC LIMIT 10
  `).all(uid);

  const stats = db.prepare(`
    SELECT COUNT(*) as pages, COALESCE(SUM(cost_usd),0) as cost_usd
    FROM requests WHERE uid = ?
  `).get(uid);

  res.json({
    uid,
    email:    user?.email || null,
    balance:  credits.balance,
    total_bought: credits.total_bought,
    pages_used:   stats.pages,
    recent_requests: recentRequests,
    recent_payments: recentPayments,
  });
}

async function handleChangePassword(req, res) {
  const uid = getUidFromRequest(req);
  if (!uid) return res.status(401).json({ error: 'Not authenticated' });
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = await bcrypt.hash(password, 10);
  db.prepare(`UPDATE users SET password_hash = ? WHERE uid = ?`).run(hash, uid);
  res.json({ ok: true });
}

// ── Project handlers ──────────────────────────────────────────────────────────

function listProjects(req, res) {
  const rows = db.prepare(`
    SELECT p.*,
      (SELECT COUNT(*) FROM project_pages WHERE project_id = p.id) as pages_done,
      (SELECT (j.updated_at - j.created_at) FROM jobs j
       WHERE j.project_id = p.id AND j.status = 'done'
       ORDER BY j.updated_at DESC LIMIT 1) as last_job_sec
    FROM projects p WHERE p.uid = ? ORDER BY p.updated_at DESC
  `).all(req.uid);
  res.json(rows);
}

function createProject(req, res) {
  const { name, filename, total_pages } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  const r = db.prepare(`
    INSERT INTO projects (uid, name, filename, total_pages) VALUES (?, ?, ?, ?)
  `).run(req.uid, name, filename || '', total_pages || 0);
  const project = db.prepare(`SELECT * FROM projects WHERE id = ?`).get(r.lastInsertRowid);
  res.json(project);
}

function getProject(req, res) {
  const project = db.prepare(`SELECT * FROM projects WHERE id = ? AND uid = ?`).get(req.params.id, req.uid);
  if (!project) return res.status(404).json({ error: 'Not found' });
  const pages_done = db.prepare(`SELECT COUNT(*) as n FROM project_pages WHERE project_id = ?`).get(project.id).n;
  res.json({ ...project, pages_done });
}

function updateProject(req, res) {
  const { name, total_pages } = req.body;
  const project = db.prepare(`SELECT * FROM projects WHERE id = ? AND uid = ?`).get(req.params.id, req.uid);
  if (!project) return res.status(404).json({ error: 'Not found' });
  db.prepare(`UPDATE projects SET name = ?, total_pages = ?, updated_at = unixepoch() WHERE id = ?`)
    .run(name ?? project.name, total_pages ?? project.total_pages, project.id);
  res.json({ ok: true });
}

function deleteProject(req, res) {
  const r = db.prepare(`DELETE FROM projects WHERE id = ? AND uid = ?`).run(req.params.id, req.uid);
  if (!r.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
}

function saveProjectPage(req, res) {
  const project = db.prepare(`SELECT * FROM projects WHERE id = ? AND uid = ?`).get(req.params.id, req.uid);
  if (!project) return res.status(404).json({ error: 'Not found' });
  const { page_num, result_json, model } = req.body;
  if (!page_num || !result_json) return res.status(400).json({ error: 'page_num and result_json required' });
  db.prepare(`
    INSERT INTO project_pages (project_id, page_num, result_json, model) VALUES (?, ?, ?, ?)
    ON CONFLICT(project_id, page_num) DO UPDATE SET result_json = excluded.result_json, model = excluded.model
  `).run(project.id, page_num, typeof result_json === 'string' ? result_json : JSON.stringify(result_json), model || '');
  db.prepare(`UPDATE projects SET updated_at = unixepoch() WHERE id = ?`).run(project.id);
  res.json({ ok: true });
}

function getProjectPages(req, res) {
  const project = db.prepare(`SELECT * FROM projects WHERE id = ? AND uid = ?`).get(req.params.id, req.uid);
  if (!project) return res.status(404).json({ error: 'Not found' });
  const pages = db.prepare(`
    SELECT page_num, result_json, model, created_at FROM project_pages
    WHERE project_id = ? ORDER BY page_num
  `).all(project.id);
  res.json(pages.map(p => {
    let result_json;
    try { result_json = JSON.parse(p.result_json); } catch { result_json = {}; }
    return { ...p, result_json };
  }));
}

function deleteProjectPage(req, res) {
  const project = db.prepare(`SELECT * FROM projects WHERE id = ? AND uid = ?`).get(req.params.id, req.uid);
  if (!project) return res.status(404).json({ error: 'Not found' });
  db.prepare(`DELETE FROM project_pages WHERE project_id = ? AND page_num = ?`).run(project.id, req.params.num);
  res.json({ ok: true });
}

// ── Job handlers ──────────────────────────────────────────────────────────────

function createJob(req, res) {
  let pages;
  try {
    pages = typeof req.body.pages === 'string' ? JSON.parse(req.body.pages) : req.body.pages;
  } catch { pages = null; }
  const { project_id, mode, lang, model } = req.body;
  const latin = req.body.latin === '1' || req.body.latin === 1 || req.body.latin === true;

  if (!project_id || !pages || !Array.isArray(pages) || pages.length === 0) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'project_id and pages[] required' });
  }
  if (!req.file) {
    return res.status(400).json({ error: 'PDF file required' });
  }

  const project = db.prepare(`SELECT * FROM projects WHERE id = ? AND uid = ?`).get(project_id, req.uid);
  if (!project) {
    fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'Project not found' });
  }

  const credits = fetchBalance(req.uid);
  if (credits < pages.length) {
    fs.unlinkSync(req.file.path);
    return res.status(402).json({ error: 'no_credits' });
  }

  const result = db.prepare(`
    INSERT INTO jobs (uid, project_id, pages, mode, lang, model, latin, pages_total, pdf_path)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(req.uid, project_id, JSON.stringify(pages), mode || 'modernize', lang || 'русский',
         model || 'claude-haiku-4-5-20251001', latin ? 1 : 0, pages.length, req.file.path);

  res.json({ job_id: result.lastInsertRowid });
}

function getJob(req, res) {
  const job = db.prepare(`SELECT * FROM jobs WHERE id = ? AND uid = ?`).get(req.params.id, req.uid);
  if (!job) return res.status(404).json({ error: 'Not found' });

  const completedPages = db.prepare(`
    SELECT page_num, result_json FROM project_pages
    WHERE project_id = ? AND page_num IN (${(() => { try { return JSON.parse(job.pages).join(','); } catch { return '0'; } })()})
  `).all(job.project_id);

  res.json({
    id: job.id,
    status: job.status,
    pages_done: job.pages_done,
    pages_total: job.pages_total,
    error: job.error,
    completed_pages: completedPages,
  });
}

function cancelJob(req, res) {
  const job = db.prepare(`SELECT * FROM jobs WHERE id = ? AND uid = ?`).get(req.params.id, req.uid);
  if (!job) return res.status(404).json({ error: 'Not found' });
  if (job.status === 'pending' || job.status === 'running') {
    db.prepare(`UPDATE jobs SET status = 'cancelled', updated_at = unixepoch() WHERE id = ?`).run(job.id);
  }
  res.json({ ok: true });
}

// ── Job image upload ──────────────────────────────────────────────────────────

app.post('/api/jobs/:id/images', requireAuth, (req, res) => {
  const job = db.prepare(`SELECT * FROM jobs WHERE id = ? AND uid = ?`).get(req.params.id, req.uid);
  if (!job) return res.status(404).json({ error: 'Not found' });
  const { page_num, image_data } = req.body;
  if (!page_num || !image_data) return res.status(400).json({ error: 'page_num and image_data required' });
  db.prepare(`INSERT OR REPLACE INTO job_page_images (job_id, page_num, image_data) VALUES (?, ?, ?)`)
    .run(job.id, page_num, image_data);
  res.json({ ok: true });
});

// ── Prompts ───────────────────────────────────────────────────────────────────

const LATIN_FIELD = `  "latin_fragments": [\n    { "original": "...", "translation": "...", "source": "..." }\n  ]`;
const NO_LATIN_FIELD = `  "latin_fragments": []`;

function getPrompts(mode, lang, latin) {
  if (mode === 'modernize') {
    return `Du bist Experte für deutsche Rechtsliteratur des 19. Jahrhunderts in Frakturschrift.
Deine Aufgabe: Lies den Text aus dem Bild (Frakturschrift) und gib ihn in modernem Deutsch wieder.

Regeln:
1. Lies den Frakturtext genau, beachte archaische Orthographie.
2. Gib den Text in moderner deutscher Rechtschreibung wieder: ſ→s, Majuskelregeln modernisieren, veraltete Schreibweisen aktualisieren.
3. Lateinische Passagen bleiben im Original.
4. Jeder Absatz des Originals = ein separates Element im Array.
5. FUßNOTEN PFLICHT. Fußnoten am Seitenende (markiert mit Ziffern 1), 2), Sternchen * usw.) vollständig modernisieren und als eigene Elemente in paragraphs aufnehmen. Keine Fußnote auslassen.
5. ${latin ? 'Lateinische Fragmente separat mit Übersetzung und Quelle auflisten.' : 'latin_fragments immer als leeres Array zurückgeben.'}
6. Antworte NUR mit gültigem JSON — kein Markdown, keine Präambel.
7. WICHTIG: Alle Anführungszeichen innerhalb von Strings müssen escaped werden: \" — niemals rohe " innerhalb eines JSON-String-Werts.

{
  "title": "Seitentitel auf modernem Deutsch, oder leerer String",
  "paragraphs": ["erster Absatz", "zweiter Absatz"],
${latin ? LATIN_FIELD : NO_LATIN_FIELD}
}`;
  } else {
    return `Ты — специалист по немецкой юридической литературе XIX века.
Читаешь тексты, набранные готическим шрифтом (Fraktur), переводишь на ${lang}.

Правила:
1. Основной текст — немецкий в Fraktur. Читай точно, учитывая архаичную орфографию.
2. ${latin ? 'Латинские слова обычно набраны антиквой — выделяй их отдельно.' : 'latin_fragments всегда возвращай пустым массивом.'}
3. ${latin ? 'Для латинских фрагментов: дай перевод + источник.' : ''}
4. Каждый абзац оригинала — отдельный элемент массива.
5. СНОСКИ ОБЯЗАТЕЛЬНЫ. Сноски в нижней части страницы (обозначены цифрами 1), 2), звёздочками * и т.п.) — переводи их полностью и включай в массив paragraphs как отдельные элементы. Не пропускай ни одну сноску.
6. Отвечай ТОЛЬКО валидным JSON — без markdown, без преамбулы.
7. ВАЖНО: все кавычки внутри строк JSON должны быть экранированы: \" — никогда не используй голые " внутри значения строки.

{
  "title": "заголовок на ${lang}, или пустая строка",
  "paragraphs": ["перевод первого абзаца", "перевод второго абзаца"],
${latin ? LATIN_FIELD : NO_LATIN_FIELD}
}`;
  }
}

// ── Job worker ────────────────────────────────────────────────────────────────

async function renderPdfPage(pdfPath, pageNum) {
  const outPrefix = pdfPath + `_p${pageNum}`;
  await execFileAsync('pdftoppm', [
    '-jpeg', '-r', '150',
    '-f', String(pageNum), '-l', String(pageNum),
    pdfPath, outPrefix
  ]);
  // pdftoppm zero-padding varies by version; find the actual output file
  const dir = path.dirname(outPrefix);
  const base = path.basename(outPrefix);
  const files = fs.readdirSync(dir).filter(f => f.startsWith(base) && f.endsWith('.jpg'));
  if (!files.length) throw new Error(`pdftoppm produced no output for page ${pageNum}`);
  const outFile = path.join(dir, files[0]);
  const b64 = fs.readFileSync(outFile).toString('base64');
  fs.unlinkSync(outFile);
  return b64;
}

async function processNextJob() {
  const job = db.prepare(`SELECT * FROM jobs WHERE status = 'pending' ORDER BY created_at ASC LIMIT 1`).get();
  if (!job) return;

  db.prepare(`UPDATE jobs SET status = 'running', updated_at = unixepoch() WHERE id = ?`).run(job.id);

  const pages = JSON.parse(job.pages);
  let pagesDone = 0;
  const prompt = getPrompts(job.mode, job.lang, job.latin === 1);

  for (const pageNum of pages) {
    const current = db.prepare(`SELECT status FROM jobs WHERE id = ?`).get(job.id);
    if (current.status === 'cancelled') {
      if (job.pdf_path) try { fs.unlinkSync(job.pdf_path); } catch {}
      return;
    }

    const credits = fetchBalance(job.uid);
    if (credits <= 0) {
      db.prepare(`UPDATE jobs SET status = 'failed', error = 'no_credits', updated_at = unixepoch() WHERE id = ?`).run(job.id);
      if (job.pdf_path) try { fs.unlinkSync(job.pdf_path); } catch {}
      return;
    }

    // Skip already processed pages
    const existing = db.prepare(`SELECT id FROM project_pages WHERE project_id = ? AND page_num = ?`).get(job.project_id, pageNum);
    if (existing) {
      pagesDone++;
      db.prepare(`UPDATE jobs SET pages_done = ?, updated_at = unixepoch() WHERE id = ?`).run(pagesDone, job.id);
      continue;
    }

    try {
      // Render PDF page on server
      const b64 = await renderPdfPage(job.pdf_path, pageNum);

      // Call Claude with exponential backoff retry on overload
      let upstream, data;
      for (let attempt = 0; attempt < 10; attempt++) {
        if (attempt > 0) {
          const delay = Math.min(30000 * Math.pow(1.5, attempt - 1), 300000); // 30s, 45s, 67s... max 5min
          console.log(`Job ${job.id} page ${pageNum} retry ${attempt} in ${Math.round(delay/1000)}s`);
          await new Promise(r => setTimeout(r, delay));
        }
        upstream = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': process.env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: job.model,
          max_tokens: 4096,
          system: prompt,
          messages: [{
            role: 'user',
            content: [
              { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: b64 } },
              { type: 'text', text: 'Lies die Seite. Jeden Absatz separat. Nur JSON.' },
            ],
          }],
        }),
        });
        data = await upstream.json();
        // Retry on overload (529) or any 5xx server error
        if (upstream.status === 529 || upstream.status >= 500) continue;
        break;
      }

      if (!upstream.ok) {
        throw new Error(data.error?.message || `Claude API error ${upstream.status}`);
      }

      const inputTokens  = data.usage?.input_tokens  || 0;
      const outputTokens = data.usage?.output_tokens || 0;
      stmtLogRequest.run(job.uid, job.model, inputTokens, outputTokens, calcCost(job.model, inputTokens, outputTokens));

      const raw = (data.content || []).map(b => b.text || '').join('');
      const start = raw.indexOf('{');
      const end   = raw.lastIndexOf('}');
      if (start === -1 || end === -1) throw new Error('No JSON in response');
      const chunk = raw.slice(start, end + 1);
      let result;
      try {
        result = JSON.parse(chunk);
      } catch {
        try {
          result = JSON.parse(jsonrepair(chunk));
        } catch {
          // Last resort: extract paragraphs as plain text so page is not lost
          const paragraphs = chunk
            .split(/\\n|\n/)
            .map(l => l.replace(/^[\s"{}[\],]+|[\s"{}[\],]+$/g, '').trim())
            .filter(l => l.length > 10);
          result = { title: '', paragraphs };
        }
      }

      // Deduct credit only after successful result
      saveBalance(job.uid, credits - 1);
      db.prepare(`INSERT OR REPLACE INTO project_pages (project_id, page_num, result_json, model) VALUES (?, ?, ?, ?)`)
        .run(job.project_id, pageNum, JSON.stringify(result), job.model);
      db.prepare(`UPDATE projects SET updated_at = unixepoch() WHERE id = ?`).run(job.project_id);

      pagesDone++;
      db.prepare(`UPDATE jobs SET pages_done = ?, updated_at = unixepoch() WHERE id = ?`).run(pagesDone, job.id);

    } catch (err) {
      console.error(`Job ${job.id} page ${pageNum} error:`, err);
      db.prepare(`UPDATE jobs SET status = 'failed', error = ?, updated_at = unixepoch() WHERE id = ?`).run(err.message, job.id);
      if (job.pdf_path) try { fs.unlinkSync(job.pdf_path); } catch {}
      return;
    }
  }

  db.prepare(`UPDATE jobs SET status = 'done', updated_at = unixepoch() WHERE id = ?`).run(job.id);
  if (job.pdf_path) try { fs.unlinkSync(job.pdf_path); } catch {}
}

// Poll for pending jobs every 3 seconds
setInterval(async () => {
  try { await processNextJob(); } catch (e) { console.error('Job worker error:', e); }
}, 3000);

// ── Public handlers ───────────────────────────────────────────────────────────

async function handleClaude(req, res) {
  if (getSetting('maintenance') === '1') {
    return res.status(503).json({ error: 'maintenance' });
  }

  const uid = getUidFromRequest(req);
  if (!uid) return res.status(401).json({ error: 'Missing X-User-Id' });

  const credits = fetchBalance(uid);
  if (credits <= 0) return res.status(402).json({ error: 'no_credits' });

  saveBalance(uid, credits - 1);

  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(req.body),
    });

    const data = await upstream.json();
    if (!upstream.ok) {
      console.error('[claude] error', upstream.status, JSON.stringify(data).slice(0, 300));
      saveBalance(uid, credits); // refund
      return res.status(upstream.status).json(data);
    }

    // Log request with token usage for economics tracking
    const model        = req.body.model || 'unknown';
    const inputTokens  = data.usage?.input_tokens  || 0;
    const outputTokens = data.usage?.output_tokens || 0;
    const costUsd      = calcCost(model, inputTokens, outputTokens);
    stmtLogRequest.run(uid, model, inputTokens, outputTokens, costUsd);

    res.json({ ...data, credits_remaining: credits - 1 });
  } catch (err) {
    saveBalance(uid, credits); // refund
    res.status(502).json({ error: err.message });
  }
}

async function handleCredits(req, res) {
  const { uid } = req.query;
  if (!uid) return res.status(400).json({ error: 'Missing uid' });
  res.json({ credits: fetchBalance(uid) });
}

async function handleProxyImage(req, res) {
  const { url } = req.query;
  if (!url || !url.startsWith('https://dlc.mpg.de/')) return res.status(400).send('Bad url');
  try {
    const r = await fetch(url);
    if (!r.ok) return res.status(r.status).send('Upstream error');
    const ct = r.headers.get('content-type') || 'image/jpeg';
    const buf = Buffer.from(await r.arrayBuffer());
    res.set('Content-Type', ct);
    res.set('Cache-Control', 'public, max-age=86400');
    res.send(buf);
  } catch (e) {
    res.status(502).send(e.message);
  }
}

async function handleProcessUrl(req, res) {
  if (getSetting('maintenance') === '1') return res.status(503).json({ error: 'maintenance' });

  const uid = getUidFromRequest(req);
  if (!uid) return res.status(401).json({ error: 'Missing X-User-Id' });

  const credits = fetchBalance(uid);
  if (credits <= 0) return res.status(402).json({ error: 'no_credits' });

  const { image_url, system, model } = req.body;
  if (!image_url || !system) return res.status(400).json({ error: 'image_url and system required' });

  // Fetch image server-side
  let imageB64, mediaType;
  try {
    const r = await fetch(image_url);
    if (!r.ok) return res.status(502).json({ error: `Image fetch failed: ${r.status}` });
    const buf = Buffer.from(await r.arrayBuffer());
    mediaType = r.headers.get('content-type')?.split(';')[0] || 'image/jpeg';
    if (!['image/jpeg','image/png','image/gif','image/webp'].includes(mediaType)) mediaType = 'image/jpeg';
    imageB64 = buf.toString('base64');
  } catch (e) {
    return res.status(502).json({ error: `Image fetch error: ${e.message}` });
  }

  saveBalance(uid, credits - 1);

  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: model || 'claude-haiku-4-5-20251001',
        max_tokens: 4000,
        system,
        messages: [{ role: 'user', content: [
          { type: 'image', source: { type: 'base64', media_type: mediaType, data: imageB64 } },
          { type: 'text', text: 'Lies die Seite. Jeden Absatz separat. Nur JSON.' }
        ]}]
      }),
    });

    const data = await upstream.json();
    if (!upstream.ok) {
      console.error('[process-url] claude error', upstream.status, JSON.stringify(data).slice(0, 300));
      saveBalance(uid, credits);
      return res.status(upstream.status).json(data);
    }

    const model2 = model || 'claude-haiku-4-5-20251001';
    stmtLogRequest.run(uid, model2, data.usage?.input_tokens || 0, data.usage?.output_tokens || 0,
      calcCost(model2, data.usage?.input_tokens || 0, data.usage?.output_tokens || 0));

    res.json({ ...data, credits_remaining: fetchBalance(uid) });
  } catch (e) {
    saveBalance(uid, credits);
    res.status(500).json({ error: e.message });
  }
}

async function handleCheckout(req, res) {
  const { uid, package_id, success_url, cancel_url } = req.body;
  const packages = getPackages();
  const pkg = packages[package_id];
  if (!pkg) return res.status(400).json({ error: 'Unknown package' });
  if (!uid)  return res.status(400).json({ error: 'Missing uid' });

  try {
    const r = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Bearer ${process.env.STRIPE_SECRET_KEY}`,
      },
      body: new URLSearchParams({
        'payment_method_types[]':  'card',
        'line_items[0][price]':    pkg.price_id,
        'line_items[0][quantity]': '1',
        'mode': 'payment',
        'success_url': success_url || 'https://fraktur.app/?payment=ok',
        'cancel_url':  cancel_url  || 'https://fraktur.app/?payment=cancel',
        'metadata[uid]':          uid,
        'metadata[package_id]':   package_id,
        'automatic_tax[enabled]': 'true',
      }),
    });

    const session = await r.json();
    if (!r.ok) return res.status(r.status).json(session);
    res.json({ url: session.url });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
}

async function handleWebhook(req, res) {
  const sig  = req.headers['stripe-signature'];
  const body = req.body;

  if (!verifyStripeSignature(body, sig, process.env.STRIPE_WEBHOOK_SECRET)) {
    return res.status(400).send('Bad signature');
  }

  const event = JSON.parse(body.toString());
  if (event.type === 'checkout.session.completed') {
    const { uid, package_id } = event.data.object.metadata || {};
    const packages = getPackages();
    const pkg = packages[package_id];
    if (uid && pkg) {
      const cur = fetchUser(uid);
      saveBalance(uid, cur.balance + pkg.credits, (cur.total_bought || 0) + pkg.credits);
      stmtLogPayment.run(uid, package_id, pkg.credits, pkg.amount_eur, event.data.object.id);
      console.log(`[payment] ${uid} +${pkg.credits} credits (${pkg.amount_eur}€)`);
    }
  }

  res.send('OK');
}

// ── YooKassa ──────────────────────────────────────────────────────────────────

async function handleCheckoutRu(req, res) {
  const { uid, package_id, success_url, cancel_url } = req.body;
  const packages = getPackages();
  const pkg = packages[package_id];
  if (!pkg) return res.status(400).json({ error: 'Unknown package' });
  if (!uid)  return res.status(400).json({ error: 'Missing uid' });

  const proxyUrl = process.env.YOOKASSA_PROXY_URL;
  if (!proxyUrl) return res.status(503).json({ error: 'YooKassa not configured' });

  // Get user email for receipt
  const user = fetchUser(uid);
  const email = user?.email || 'noreply@fraktur.app';

  const idempotenceKey = crypto.randomUUID();
  const amountRub = pkg.amount_rub || Math.round(pkg.amount_eur * 95);

  try {
    const r = await fetch(proxyUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        _idempotence_key: idempotenceKey,
        amount:      { value: amountRub.toFixed(2), currency: 'RUB' },
        capture:     true,
        confirmation: {
          type:       'redirect',
          return_url: success_url || 'https://fraktur.app/account?payment=ok',
        },
        description: `Fraktur.app — ${pkg.credits} pages`,
        metadata:    { uid, package_id },
        receipt: {
          customer: { email },
          items: [{
            description: `Fraktur.app — ${pkg.credits} страниц`,
            quantity:    '1.00',
            amount:      { value: amountRub.toFixed(2), currency: 'RUB' },
            vat_code:    1,
            payment_subject: 'service',
            payment_mode:    'full_payment',
          }],
        },
      }),
    });

    const payment = await r.json();
    if (!r.ok) return res.status(r.status).json(payment);
    res.json({ url: payment.confirmation.confirmation_url });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
}

async function handleYooKassaWebhook(req, res) {
  const event = req.body;
  if (!event || event.event !== 'payment.succeeded') return res.send('OK');

  const { uid, package_id } = event.object?.metadata || {};
  const packages = getPackages();
  const pkg = packages[package_id];
  if (uid && pkg) {
    const cur = fetchUser(uid);
    saveBalance(uid, cur.balance + pkg.credits, (cur.total_bought || 0) + pkg.credits);
    const amount = parseFloat(event.object?.amount?.value || 0);
    stmtLogPayment.run(uid, package_id, pkg.credits, amount / 95, event.object.id); // store as EUR equiv
    console.log(`[yookassa] ${uid} +${pkg.credits} credits`);
  }

  res.send('OK');
}

// ── Admin handlers ────────────────────────────────────────────────────────────

function adminStats(req, res) {
  const period = req.query.period || '30'; // days
  const since  = Math.floor(Date.now() / 1000) - parseInt(period) * 86400;

  const revenue = db.prepare(`SELECT COALESCE(SUM(amount_eur),0) as total FROM payments WHERE created_at >= ?`).get(since).total;
  const costUsd = db.prepare(`SELECT COALESCE(SUM(cost_usd),0) as total FROM requests WHERE created_at >= ?`).get(since).total;
  const pages   = db.prepare(`SELECT COUNT(*) as total FROM requests WHERE created_at >= ?`).get(since).total;
  const users   = db.prepare(`SELECT COUNT(DISTINCT uid) as total FROM requests WHERE created_at >= ?`).get(since).total;
  const totalUsers = db.prepare(`SELECT COUNT(*) as total FROM credits`).get().total;

  // Daily breakdown for chart (last N days)
  const daily = db.prepare(`
    SELECT
      date(created_at, 'unixepoch') as day,
      COUNT(*) as pages,
      SUM(cost_usd) as cost_usd
    FROM requests WHERE created_at >= ?
    GROUP BY day ORDER BY day
  `).all(since);

  const dailyPayments = db.prepare(`
    SELECT
      date(created_at, 'unixepoch') as day,
      SUM(amount_eur) as revenue_eur
    FROM payments WHERE created_at >= ?
    GROUP BY day ORDER BY day
  `).all(since);

  // Model breakdown
  const byModel = db.prepare(`
    SELECT model, COUNT(*) as pages, SUM(cost_usd) as cost_usd
    FROM requests WHERE created_at >= ?
    GROUP BY model ORDER BY pages DESC
  `).all(since);

  res.json({ revenue_eur: revenue, cost_usd: costUsd, pages, users, total_users: totalUsers, daily, daily_payments: dailyPayments, by_model: byModel });
}

function adminUsers(req, res) {
  const limit  = parseInt(req.query.limit)  || 50;
  const offset = parseInt(req.query.offset) || 0;
  const search = req.query.search || '';

  const rows = db.prepare(`
    SELECT
      c.uid,
      u.email,
      c.balance,
      c.total_bought,
      c.created_at,
      COALESCE(r.pages, 0)    as pages_used,
      COALESCE(r.cost_usd, 0) as cost_usd,
      COALESCE(p.paid_eur, 0) as paid_eur,
      r.last_used
    FROM credits c
    LEFT JOIN users u ON u.uid = c.uid
    LEFT JOIN (
      SELECT uid, COUNT(*) as pages, SUM(cost_usd) as cost_usd, MAX(created_at) as last_used
      FROM requests GROUP BY uid
    ) r ON r.uid = c.uid
    LEFT JOIN (
      SELECT uid, SUM(amount_eur) as paid_eur FROM payments GROUP BY uid
    ) p ON p.uid = c.uid
    WHERE c.uid LIKE ? OR u.email LIKE ?
    ORDER BY c.created_at DESC
    LIMIT ? OFFSET ?
  `).all(`%${search}%`, `%${search}%`, limit, offset);

  const total = db.prepare(`
    SELECT COUNT(*) as n FROM credits c
    LEFT JOIN users u ON u.uid = c.uid
    WHERE c.uid LIKE ? OR u.email LIKE ?
  `).get(`%${search}%`, `%${search}%`).n;
  res.json({ rows, total });
}

function adminPayments(req, res) {
  const limit  = parseInt(req.query.limit)  || 50;
  const offset = parseInt(req.query.offset) || 0;

  const rows = db.prepare(`
    SELECT * FROM payments ORDER BY created_at DESC LIMIT ? OFFSET ?
  `).all(limit, offset);
  const total = db.prepare(`SELECT COUNT(*) as n FROM payments`).get().n;
  res.json({ rows, total });
}

function adminRequests(req, res) {
  const limit  = parseInt(req.query.limit)  || 100;
  const offset = parseInt(req.query.offset) || 0;
  const uid    = req.query.uid || '';

  const rows = uid
    ? db.prepare(`SELECT * FROM requests WHERE uid = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(uid, limit, offset)
    : db.prepare(`SELECT * FROM requests ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(limit, offset);
  res.json({ rows });
}

function adminSetCredits(req, res) {
  const { uid, delta, reason } = req.body;
  if (!uid || delta === undefined) return res.status(400).json({ error: 'uid and delta required' });
  const cur = fetchUser(uid);
  const newBalance = Math.max(0, cur.balance + parseInt(delta));
  saveBalance(uid, newBalance, cur.total_bought);
  console.log(`[admin] ${uid} credits ${cur.balance} → ${newBalance} (${reason || 'manual'})`);
  res.json({ uid, balance: newBalance });
}

function adminGetSettings(req, res) {
  const packages    = getSetting('packages');
  const maintenance = getSetting('maintenance', '0');
  const promoEnabled = getSetting('promo_enabled', '1');
  const promoCount  = db.prepare(`SELECT COUNT(*) as n FROM users`).get().n;
  res.json({
    packages: packages ? JSON.parse(packages) : getPackages(),
    maintenance: maintenance === '1',
    promo_enabled: promoEnabled === '1',
    promo_count: promoCount,
  });
}

function adminSaveSettings(req, res) {
  const { packages, maintenance, promo_enabled } = req.body;
  if (packages)    stmtSetSetting.run('packages', JSON.stringify(packages));
  if (maintenance !== undefined) stmtSetSetting.run('maintenance', maintenance ? '1' : '0');
  if (promo_enabled !== undefined) stmtSetSetting.run('promo_enabled', promo_enabled ? '1' : '0');
  res.json({ ok: true });
}

// ── Admin HTML ────────────────────────────────────────────────────────────────

function serveAdmin(req, res) {
  res.send(ADMIN_HTML);
}

const ADMIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Fraktur Admin</title>
<link rel="icon" type="image/png" href="/logo.png">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg: #f3f4f6; --surface: #fff; --border: #e5e7eb; --text: #111827;
  --text-2: #6b7280; --accent: #2563eb; --green: #059669; --red: #dc2626;
  --radius: 8px;
}
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); font-size: 14px; }
#header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 0 1.5rem; height: 52px; display: flex; align-items: center; gap: 1rem; position: sticky; top: 0; z-index: 10; }
#header h1 { font-size: 1rem; font-weight: 600; }
.tabs { display: flex; gap: 0.25rem; }
.tab { padding: 0.35rem 0.9rem; border: none; background: none; font-size: 0.82rem; cursor: pointer; border-radius: 6px; color: var(--text-2); font-family: inherit; }
.tab.active { background: #eff6ff; color: var(--accent); font-weight: 600; }
#app { max-width: 1200px; margin: 0 auto; padding: 1.25rem; display: flex; flex-direction: column; gap: 1rem; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1rem; }
.card h2 { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.07em; color: var(--text-2); margin-bottom: 0.75rem; }
.kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 0.75rem; }
.kpi { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 0.9rem 1rem; }
.kpi .label { font-size: 0.72rem; color: var(--text-2); font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }
.kpi .value { font-size: 1.6rem; font-weight: 700; margin-top: 0.2rem; line-height: 1; }
.kpi .sub { font-size: 0.72rem; color: var(--text-2); margin-top: 0.2rem; }
.kpi.green .value { color: var(--green); }
.kpi.red   .value { color: var(--red); }
.kpi.blue  .value { color: var(--accent); }
.period-bar { display: flex; gap: 0.4rem; margin-bottom: 1rem; }
.period-btn { padding: 0.25rem 0.7rem; border: 1px solid var(--border); border-radius: 99px; background: var(--surface); font-size: 0.75rem; cursor: pointer; font-family: inherit; color: var(--text-2); }
.period-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
th { text-align: left; padding: 0.4rem 0.6rem; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-2); border-bottom: 1px solid var(--border); }
td { padding: 0.45rem 0.6rem; border-bottom: 1px solid var(--border); color: var(--text); }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #f9fafb; }
.badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 99px; font-size: 0.7rem; font-weight: 600; }
.badge.green { background: #dcfce7; color: #166534; }
.badge.blue  { background: #dbeafe; color: #1e40af; }
.charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
canvas { max-height: 220px; }
input[type=text], input[type=number] { padding: 0.3rem 0.6rem; border: 1px solid var(--border); border-radius: 6px; font-size: 0.82rem; font-family: inherit; width: 100%; }
.btn { padding: 0.35rem 0.9rem; border: none; border-radius: 6px; font-size: 0.82rem; font-weight: 600; cursor: pointer; font-family: inherit; }
.btn-primary { background: var(--accent); color: #fff; }
.btn-sm { padding: 0.2rem 0.6rem; font-size: 0.75rem; }
.row { display: flex; gap: 0.5rem; align-items: center; }
.pager { display: flex; gap: 0.5rem; align-items: center; margin-top: 0.75rem; font-size: 0.8rem; color: var(--text-2); }
.section { display: none; }
.section.active { display: block; }
.model-row { display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0; border-bottom: 1px solid var(--border); font-size: 0.82rem; }
.model-row:last-child { border: none; }
.maintenance-banner { background: #fef3c7; border: 1px solid #fcd34d; border-radius: var(--radius); padding: 0.6rem 1rem; font-size: 0.82rem; color: #92400e; margin-bottom: 0.75rem; display: none; }
</style>
</head>
<body>
<div id="header">
  <h1>🔒 Fraktur Admin</h1>
  <div class="tabs">
    <button class="tab active" onclick="showSection('dashboard')">Dashboard</button>
    <button class="tab" onclick="showSection('users')">Users</button>
    <button class="tab" onclick="showSection('payments')">Payments</button>
    <button class="tab" onclick="showSection('economics')">Economics</button>
    <button class="tab" onclick="showSection('settings')">Settings</button>
  </div>
</div>

<div id="app">

<!-- Dashboard -->
<div id="s-dashboard" class="section active">
  <div class="period-bar">
    <button class="period-btn active" onclick="setPeriod(7)">7d</button>
    <button class="period-btn" onclick="setPeriod(30)">30d</button>
    <button class="period-btn" onclick="setPeriod(90)">90d</button>
  </div>
  <div class="kpi-grid" id="kpis"></div>
  <div class="charts-row" style="margin-top:0.75rem">
    <div class="card"><h2>Revenue vs API Cost (€)</h2><canvas id="chart-revenue"></canvas></div>
    <div class="card"><h2>Pages processed per day</h2><canvas id="chart-pages"></canvas></div>
  </div>
  <div class="card" style="margin-top:0.75rem">
    <h2>By model</h2>
    <div id="by-model"></div>
  </div>
</div>

<!-- Users -->
<div id="s-users" class="section">
  <div class="card">
    <div class="row" style="margin-bottom:0.75rem">
      <input type="text" id="user-search" placeholder="Search by UID…" style="max-width:320px" oninput="loadUsers()">
      <div style="flex:1"></div>
      <span id="user-count" style="font-size:0.8rem;color:var(--text-2)"></span>
    </div>
    <table>
      <thead><tr><th>Email</th><th>Balance</th><th>Bought</th><th>Pages used</th><th>API cost</th><th>Paid</th><th>Joined</th><th></th></tr></thead>
      <tbody id="users-tbody"></tbody>
    </table>
    <div class="pager">
      <button class="btn" onclick="usersPage(-1)">← Prev</button>
      <span id="users-pager-info"></span>
      <button class="btn" onclick="usersPage(1)">Next →</button>
    </div>
  </div>
</div>

<!-- Payments -->
<div id="s-payments" class="section">
  <div class="card">
    <table>
      <thead><tr><th>Date</th><th>UID</th><th>Package</th><th>Credits</th><th>Amount</th><th>Stripe ID</th></tr></thead>
      <tbody id="payments-tbody"></tbody>
    </table>
    <div class="pager">
      <button class="btn" onclick="paymentsPage(-1)">← Prev</button>
      <span id="payments-pager-info"></span>
      <button class="btn" onclick="paymentsPage(1)">Next →</button>
    </div>
  </div>
</div>

<!-- Economics -->
<div id="s-economics" class="section">
  <div class="period-bar">
    <button class="period-btn active" onclick="setPeriodEcon(7)">7d</button>
    <button class="period-btn" onclick="setPeriodEcon(30)">30d</button>
    <button class="period-btn" onclick="setPeriodEcon(90)">90d</button>
  </div>
  <div class="kpi-grid" id="econ-kpis"></div>
  <div class="charts-row" style="margin-top:0.75rem">
    <div class="card"><h2>Margin % per day</h2><canvas id="chart-margin"></canvas></div>
    <div class="card"><h2>Revenue vs Cost (cumulative €)</h2><canvas id="chart-cumulative"></canvas></div>
  </div>
</div>

<!-- Settings -->
<div id="s-settings" class="section">
  <div class="card" style="max-width:600px">
    <h2>Promo campaign</h2>
    <div class="row" style="margin-top:0.5rem">
      <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer">
        <input type="checkbox" id="promo-toggle" onchange="togglePromo()">
        Give 10 free pages to first 100 new users
      </label>
      <span id="promo-count" style="margin-left:1rem;color:var(--muted);font-size:0.82rem"></span>
    </div>

    <h2 style="margin-top:1.5rem">Maintenance mode</h2>
    <div class="row" style="margin-top:0.5rem">
      <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer">
        <input type="checkbox" id="maintenance-toggle" onchange="toggleMaintenance()">
        Disable site for users (show "maintenance" error)
      </label>
    </div>
  </div>
  <div class="card" style="max-width:600px;margin-top:0.75rem">
    <h2>Packages</h2>
    <div id="pkg-editor"></div>
    <button class="btn btn-primary" style="margin-top:0.75rem" onclick="savePackages()">Save packages</button>
  </div>
  <div class="card" style="max-width:600px;margin-top:0.75rem">
    <h2>Add credits manually</h2>
    <div class="row" style="margin-top:0.5rem;flex-wrap:wrap;gap:0.5rem">
      <input type="text" id="credit-uid" placeholder="User UID" style="flex:2;min-width:200px">
      <input type="number" id="credit-delta" placeholder="± credits" style="flex:1;min-width:80px">
      <button class="btn btn-primary" onclick="addCredits()">Apply</button>
    </div>
    <div id="credit-result" style="margin-top:0.5rem;font-size:0.8rem;color:var(--green)"></div>
  </div>
</div>

</div>

<script>
let currentPeriod = 7;
let currentPeriodEcon = 7;
let usersOffset = 0;
let paymentsOffset = 0;
const PAGE = 50;

let chartRevenue, chartPages, chartMargin, chartCumulative;

function showSection(name) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('s-' + name).classList.add('active');
  event.target.classList.add('active');
  if (name === 'dashboard' || name === 'economics') loadStats();
  if (name === 'users')    loadUsers();
  if (name === 'payments') loadPayments();
  if (name === 'settings') loadSettings();
}

function setPeriod(d) {
  currentPeriod = d;
  document.querySelectorAll('#s-dashboard .period-btn').forEach((b, i) => b.classList.toggle('active', [7,30,90][i] === d));
  loadStats();
}
function setPeriodEcon(d) {
  currentPeriodEcon = d;
  document.querySelectorAll('#s-economics .period-btn').forEach((b, i) => b.classList.toggle('active', [7,30,90][i] === d));
  loadStats();
}

async function api(path) {
  const r = await fetch(path);
  return r.json();
}
async function post(path, body) {
  const r = await fetch(path, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
  return r.json();
}

function fmt(n, decimals=2) { return Number(n||0).toFixed(decimals); }
function fmtDate(ts) { return ts ? new Date(ts*1000).toLocaleDateString() : '—'; }
function shortUid(uid) { return uid ? uid.slice(0,8)+'…' : '—'; }

async function loadStats() {
  const period = document.getElementById('s-economics').classList.contains('active') ? currentPeriodEcon : currentPeriod;
  const d = await api('/admin/api/stats?period=' + period);

  // KPI cards
  const costEur = d.cost_usd * 0.93;
  const margin  = d.revenue_eur > 0 ? ((d.revenue_eur - costEur) / d.revenue_eur * 100) : 0;

  document.getElementById('kpis').innerHTML = \`
    <div class="kpi green"><div class="label">Revenue</div><div class="value">€\${fmt(d.revenue_eur)}</div><div class="sub">last \${period} days</div></div>
    <div class="kpi red"><div class="label">API Cost</div><div class="value">$\${fmt(d.cost_usd)}</div><div class="sub">≈ €\${fmt(costEur)}</div></div>
    <div class="kpi blue"><div class="label">Gross Margin</div><div class="value">\${fmt(margin, 0)}%</div><div class="sub">€\${fmt(d.revenue_eur - costEur)} profit</div></div>
    <div class="kpi"><div class="label">Pages</div><div class="value">\${d.pages}</div><div class="sub">processed</div></div>
    <div class="kpi"><div class="label">Active users</div><div class="value">\${d.users}</div><div class="sub">of \${d.total_users} total</div></div>
    <div class="kpi"><div class="label">Avg cost/page</div><div class="value">$\${d.pages > 0 ? fmt(d.cost_usd/d.pages, 4) : '0'}</div><div class="sub">API cost per page</div></div>
  \`;

  document.getElementById('econ-kpis').innerHTML = \`
    <div class="kpi green"><div class="label">Revenue</div><div class="value">€\${fmt(d.revenue_eur)}</div></div>
    <div class="kpi red"><div class="label">API Cost</div><div class="value">€\${fmt(costEur)}</div><div class="sub">$\${fmt(d.cost_usd)} USD</div></div>
    <div class="kpi blue"><div class="label">Gross Profit</div><div class="value">€\${fmt(d.revenue_eur - costEur)}</div></div>
    <div class="kpi \${margin >= 50 ? 'green' : 'red'}"><div class="label">Margin</div><div class="value">\${fmt(margin,0)}%</div></div>
    <div class="kpi"><div class="label">Cost/page</div><div class="value">$\${d.pages > 0 ? fmt(d.cost_usd/d.pages,4) : '0'}</div></div>
    <div class="kpi"><div class="label">Revenue/page</div><div class="value">€\${d.pages > 0 ? fmt(d.revenue_eur/d.pages,4) : '0'}</div></div>
  \`;

  // Build day-indexed maps
  const dayMap = {};
  (d.daily || []).forEach(r => { dayMap[r.day] = { pages: r.pages, cost: r.cost_usd * 0.93 }; });
  (d.daily_payments || []).forEach(r => {
    if (!dayMap[r.day]) dayMap[r.day] = { pages: 0, cost: 0 };
    dayMap[r.day].revenue = r.revenue_eur;
  });

  const days    = Object.keys(dayMap).sort();
  const revenues = days.map(d => dayMap[d].revenue || 0);
  const costs    = days.map(d => dayMap[d].cost    || 0);
  const pages    = days.map(d => dayMap[d].pages   || 0);
  const margins  = days.map((d, i) => revenues[i] > 0 ? ((revenues[i] - costs[i]) / revenues[i] * 100) : null);

  // Cumulative
  let cumRev = 0, cumCost = 0;
  const cumRevArr  = revenues.map(v => (cumRev  += v));
  const cumCostArr = costs.map(v    => (cumCost += v));

  drawChart('chartRevenue', chartRevenue, days,
    [{ label:'Revenue €', data: revenues, borderColor:'#059669', backgroundColor:'rgba(5,150,105,0.1)', fill:true },
     { label:'API Cost €', data: costs, borderColor:'#dc2626', backgroundColor:'rgba(220,38,38,0.1)', fill:true }]);
  chartRevenue = window._charts?.chartRevenue;

  drawChart('chart-pages', null, days,
    [{ label:'Pages', data: pages, borderColor:'#2563eb', backgroundColor:'rgba(37,99,235,0.1)', fill:true }]);

  drawChart('chart-margin', null, days,
    [{ label:'Margin %', data: margins, borderColor:'#7c3aed', backgroundColor:'rgba(124,58,237,0.08)', fill:true, spanGaps:true }]);

  drawChart('chart-cumulative', null, days,
    [{ label:'Revenue €', data: cumRevArr, borderColor:'#059669' },
     { label:'Cost €', data: cumCostArr, borderColor:'#dc2626' }]);

  // By model
  document.getElementById('by-model').innerHTML = (d.by_model || []).map(m => \`
    <div class="model-row">
      <span><strong>\${m.model.split('-').slice(1,3).join('-')}</strong></span>
      <span>\${m.pages} pages</span>
      <span style="color:var(--red)">$\${fmt(m.cost_usd,4)}/pg avg · $\${fmt(m.cost_usd)} total</span>
    </div>
  \`).join('') || '<div style="color:var(--text-2);font-size:0.82rem">No data yet</div>';
}

function drawChart(id, existing, labels, datasets) {
  const canvas = document.getElementById(id);
  if (!canvas) return;
  if (existing) existing.destroy();
  return new Chart(canvas, {
    type: 'line',
    data: { labels, datasets: datasets.map(d => ({ tension:0.3, pointRadius:2, ...d })) },
    options: { responsive:true, plugins:{ legend:{ labels:{ font:{ size:11 } } } }, scales:{ y:{ beginAtZero:true } } }
  });
}

async function loadUsers() {
  const search = document.getElementById('user-search').value;
  const d = await api(\`/admin/api/users?limit=\${PAGE}&offset=\${usersOffset}&search=\${encodeURIComponent(search)}\`);
  document.getElementById('user-count').textContent = \`\${d.total} users\`;
  document.getElementById('users-pager-info').textContent = \`\${usersOffset+1}–\${Math.min(usersOffset+PAGE, d.total)} of \${d.total}\`;
  document.getElementById('users-tbody').innerHTML = d.rows.map(u => \`
    <tr>
      <td>\${u.email || '<span style="color:#999;font-size:0.75rem">'+u.uid.slice(0,8)+'…</span>'}</td>
      <td><span class="badge \${u.balance>0?'green':'blue'}">\${u.balance}</span></td>
      <td>\${u.total_bought}</td>
      <td>\${u.pages_used}</td>
      <td style="color:var(--red)">$\${fmt(u.cost_usd,4)}</td>
      <td style="color:var(--green)">€\${fmt(u.paid_eur)}</td>
      <td>\${fmtDate(u.created_at)}</td>
      <td><button class="btn btn-sm btn-primary" onclick="quickCredit('\${u.uid}')">+ credits</button></td>
    </tr>
  \`).join('');
}

function quickCredit(uid) {
  const delta = prompt(\`Add/remove credits for \${uid.slice(0,8)}…\nEnter number (negative to subtract):\`);
  if (!delta) return;
  post('/admin/api/credits', { uid, delta: parseInt(delta), reason: 'manual via admin' })
    .then(d => { alert(\`New balance: \${d.balance}\`); loadUsers(); });
}

function usersPage(dir) {
  usersOffset = Math.max(0, usersOffset + dir * PAGE);
  loadUsers();
}

async function loadPayments() {
  const d = await api(\`/admin/api/payments?limit=\${PAGE}&offset=\${paymentsOffset}\`);
  document.getElementById('payments-pager-info').textContent = \`\${paymentsOffset+1}–\${Math.min(paymentsOffset+PAGE, d.total)} of \${d.total}\`;
  document.getElementById('payments-tbody').innerHTML = d.rows.map(p => \`
    <tr>
      <td>\${fmtDate(p.created_at)}</td>
      <td style="font-family:monospace;font-size:0.75rem">\${shortUid(p.uid)}</td>
      <td>\${p.package_id}</td>
      <td>\${p.credits}</td>
      <td style="color:var(--green)">€\${fmt(p.amount_eur)}</td>
      <td style="font-family:monospace;font-size:0.72rem">\${p.stripe_id||'—'}</td>
    </tr>
  \`).join('');
}
function paymentsPage(dir) {
  paymentsOffset = Math.max(0, paymentsOffset + dir * PAGE);
  loadPayments();
}

async function loadSettings() {
  const d = await api('/admin/api/settings');
  document.getElementById('maintenance-toggle').checked = d.maintenance;
  document.getElementById('promo-toggle').checked = d.promo_enabled;
  document.getElementById('promo-count').textContent = \`\${d.promo_count} / 100 users registered\`;
  const pkgs = d.packages;
  document.getElementById('pkg-editor').innerHTML = Object.entries(pkgs).map(([id, pkg]) => \`
    <div style="margin-bottom:0.75rem">
      <div style="font-weight:600;font-size:0.82rem;margin-bottom:0.3rem">\${id}</div>
      <div class="row">
        <label style="font-size:0.75rem;color:var(--text-2);white-space:nowrap">Credits</label>
        <input type="number" id="pkg-\${id}-credits" value="\${pkg.credits}" style="width:80px">
        <label style="font-size:0.75rem;color:var(--text-2);white-space:nowrap">Price €</label>
        <input type="number" id="pkg-\${id}-eur" value="\${pkg.amount_eur}" step="0.01" style="width:80px">
        <label style="font-size:0.75rem;color:var(--text-2);white-space:nowrap">Stripe Price ID</label>
        <input type="text" id="pkg-\${id}-price-id" value="\${pkg.price_id||''}">
      </div>
    </div>
  \`).join('');
}

async function toggleMaintenance() {
  const on = document.getElementById('maintenance-toggle').checked;
  await post('/admin/api/settings', { maintenance: on });
}

async function togglePromo() {
  const on = document.getElementById('promo-toggle').checked;
  await post('/admin/api/settings', { promo_enabled: on });
}

async function savePackages() {
  const d = await api('/admin/api/settings');
  const pkgs = d.packages;
  Object.keys(pkgs).forEach(id => {
    pkgs[id].credits    = parseInt(document.getElementById('pkg-'+id+'-credits').value);
    pkgs[id].amount_eur = parseFloat(document.getElementById('pkg-'+id+'-eur').value);
    pkgs[id].price_id   = document.getElementById('pkg-'+id+'-price-id').value;
  });
  await post('/admin/api/settings', { packages: pkgs });
  alert('Saved!');
}

async function addCredits() {
  const uid   = document.getElementById('credit-uid').value.trim();
  const delta = parseInt(document.getElementById('credit-delta').value);
  if (!uid || isNaN(delta)) return;
  const d = await post('/admin/api/credits', { uid, delta, reason: 'manual via admin' });
  document.getElementById('credit-result').textContent = \`✓ New balance: \${d.balance} credits\`;
}

// Init
loadStats();
</script>
</body>
</html>`;

// ── Stripe HMAC-SHA256 verification ──────────────────────────────────────────

function verifyStripeSignature(body, header, secret) {
  if (!header || !secret) return false;
  const parts = Object.fromEntries(header.split(',').map(p => p.split('=')));
  const { t: ts, v1 } = parts;
  if (!ts || !v1) return false;

  const payload  = `${ts}.${body}`;
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(v1));
}

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => console.log(`gothic-reader listening on :${PORT}`));
