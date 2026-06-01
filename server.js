const express = require('express');
const Database = require('better-sqlite3');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'prode2026_secret_cambiame';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'prode.db');

const db = new Database(DB_PATH);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ========================
// NODEMAILER
// ========================
function createTransporter() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}

// ========================
// INIT DB
// ========================
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS reset_tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    match_id TEXT NOT NULL,
    home_score INTEGER,
    away_score INTEGER,
    pen_home INTEGER,
    pen_away INTEGER,
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, match_id)
  );

  CREATE TABLE IF NOT EXISTS real_results (
    match_id TEXT PRIMARY KEY,
    home_score INTEGER,
    away_score INTEGER,
    pen_home INTEGER,
    pen_away INTEGER,
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS group_predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    group_key TEXT NOT NULL,
    pos1 TEXT, pos2 TEXT, pos3 TEXT, pos4 TEXT,
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, group_key)
  );

  CREATE TABLE IF NOT EXISTS group_results (
    group_key TEXT PRIMARY KEY,
    pos1 TEXT, pos2 TEXT, pos3 TEXT, pos4 TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS award_predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    award_id TEXT NOT NULL,
    value TEXT,
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, award_id)
  );

  CREATE TABLE IF NOT EXISTS award_results (
    award_id TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
  );
`);

// ========================
// MIDDLEWARE AUTH
// ========================
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'No autorizado' });
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// ========================
// AUTH ENDPOINTS
// ========================

// Registro
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name?.trim() || !email?.trim() || !password)
    return res.status(400).json({ error: 'Nombre, email y contraseña requeridos' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Email inválido' });
  if (password.length < 6)
    return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });

  const hash = await bcrypt.hash(password, 10);
  const id = 'u_' + Date.now() + '_' + crypto.randomBytes(3).toString('hex');
  try {
    db.prepare('INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)')
      .run(id, name.trim(), email.toLowerCase().trim(), hash);
    const token = jwt.sign({ id, name: name.trim(), email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id, name: name.trim(), email, must_change_password: 0 } });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(400).json({ error: 'Ese email ya está registrado' });
    res.status(500).json({ error: e.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (!user) return res.status(401).json({ error: 'Email o contraseña incorrectos' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Email o contraseña incorrectos' });

  const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, must_change_password: user.must_change_password } });
});

// Cambiar contraseña (usuario logueado)
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { current_password, new_password } = req.body;
  if (!new_password || new_password.length < 6)
    return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 6 caracteres' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

  // Si must_change_password está activo, no pedimos la contraseña actual
  if (!user.must_change_password) {
    if (!current_password) return res.status(400).json({ error: 'Ingresá tu contraseña actual' });
    const ok = await bcrypt.compare(current_password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
  }

  const hash = await bcrypt.hash(new_password, 10);
  db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?').run(hash, req.user.id);
  res.json({ ok: true });
});

// Solicitar reset de contraseña
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email requerido' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  // Siempre respondemos OK para no revelar si el email existe
  if (!user) return res.json({ ok: true });

  // Generar token random
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 1000 * 60 * 60).toISOString(); // 1 hora

  db.prepare('DELETE FROM reset_tokens WHERE user_id = ?').run(user.id);
  db.prepare('INSERT INTO reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, user.id, expires);

  // Generar contraseña temporal random
  const tempPassword = crypto.randomBytes(5).toString('hex'); // ej: "a3f9c2b1e5"
  const tempHash = await bcrypt.hash(tempPassword, 10);

  db.prepare('UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?').run(tempHash, user.id);

  // Enviar mail
  try {
    const transporter = createTransporter();
    await transporter.sendMail({
      from: `"Prode Mundial 2026 🏆" <${process.env.SMTP_USER}>`,
      to: user.email,
      subject: '🔑 Tu nueva contraseña temporal - Prode Mundial 2026',
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0a0e1a;color:#f1f5f9;padding:2rem;border-radius:12px">
          <h1 style="color:#f59e0b;font-size:1.5rem;margin-bottom:0.5rem">Prode Mundial 2026 🏆</h1>
          <p style="color:#94a3b8;margin-bottom:1.5rem">Hola <strong style="color:#f1f5f9">${user.name}</strong>, recibimos tu pedido de restablecer contraseña.</p>
          <div style="background:#1a2235;border:1px solid rgba(245,158,11,0.3);border-radius:8px;padding:1.25rem;text-align:center;margin-bottom:1.5rem">
            <p style="color:#94a3b8;font-size:0.85rem;margin-bottom:0.5rem">Tu contraseña temporal es:</p>
            <p style="font-size:1.8rem;font-weight:700;letter-spacing:4px;color:#f59e0b;font-family:monospace">${tempPassword}</p>
          </div>
          <p style="color:#94a3b8;font-size:0.85rem">⚠️ Esta contraseña es de un solo uso. Al ingresar, el sistema te pedirá que la cambies por una nueva.</p>
          <p style="color:#64748b;font-size:0.75rem;margin-top:1rem">Si no pediste este cambio, ignorá este mail.</p>
        </div>
      `
    });
  } catch (e) {
    console.error('Error enviando mail:', e.message);
    return res.status(500).json({ error: 'No se pudo enviar el email. Revisá la configuración SMTP.' });
  }

  res.json({ ok: true });
});

// ========================
// USERS (lista pública para el selector)
// ========================
app.get('/api/users', requireAuth, (req, res) => {
  const users = db.prepare('SELECT id, name, email FROM users ORDER BY created_at').all();
  res.json(users);
});

// ========================
// PREDICCIONES PARTIDOS
// ========================
app.get('/api/predictions', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM predictions').all();
  const result = {};
  rows.forEach(r => {
    if (!result[r.user_id]) result[r.user_id] = {};
    result[r.user_id][r.match_id] = { h: r.home_score, a: r.away_score, ph: r.pen_home, pa: r.pen_away };
  });
  res.json(result);
});

app.post('/api/predictions', requireAuth, (req, res) => {
  const { user_id, match_id, h, a, ph, pa } = req.body;
  // Solo podés guardar tus propias predicciones
  if (req.user.id !== user_id) return res.status(403).json({ error: 'No podés editar predicciones de otro jugador' });
  if (!match_id || h === undefined || a === undefined) return res.status(400).json({ error: 'Datos incompletos' });
  db.prepare(`
    INSERT INTO predictions (user_id, match_id, home_score, away_score, pen_home, pen_away, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, match_id) DO UPDATE SET
      home_score=excluded.home_score, away_score=excluded.away_score,
      pen_home=excluded.pen_home, pen_away=excluded.pen_away, updated_at=datetime('now')
  `).run(user_id, match_id, h, a, ph ?? null, pa ?? null);
  res.json({ ok: true });
});

// ========================
// RESULTADOS REALES
// ========================
app.get('/api/results', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM real_results').all();
  const result = {};
  rows.forEach(r => { result[r.match_id] = { h: r.home_score, a: r.away_score, ph: r.pen_home, pa: r.pen_away }; });
  res.json(result);
});

app.post('/api/results', requireAuth, (req, res) => {
  const { match_id, h, a, ph, pa } = req.body;
  if (!match_id || h === undefined || a === undefined) return res.status(400).json({ error: 'Datos incompletos' });
  db.prepare(`
    INSERT INTO real_results (match_id, home_score, away_score, pen_home, pen_away, updated_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(match_id) DO UPDATE SET
      home_score=excluded.home_score, away_score=excluded.away_score,
      pen_home=excluded.pen_home, pen_away=excluded.pen_away, updated_at=datetime('now')
  `).run(match_id, h, a, ph ?? null, pa ?? null);
  res.json({ ok: true });
});

// ========================
// PREDICCIONES GRUPOS
// ========================
app.get('/api/group-predictions', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM group_predictions').all();
  const result = {};
  rows.forEach(r => {
    if (!result[r.user_id]) result[r.user_id] = {};
    result[r.user_id][r.group_key] = [r.pos1, r.pos2, r.pos3, r.pos4];
  });
  res.json(result);
});

app.post('/api/group-predictions', requireAuth, (req, res) => {
  const { user_id, group_key, positions } = req.body;
  if (req.user.id !== user_id) return res.status(403).json({ error: 'No podés editar predicciones de otro jugador' });
  if (!group_key || !positions || positions.length !== 4) return res.status(400).json({ error: 'Datos incompletos' });
  db.prepare(`
    INSERT INTO group_predictions (user_id, group_key, pos1, pos2, pos3, pos4, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, group_key) DO UPDATE SET
      pos1=excluded.pos1, pos2=excluded.pos2, pos3=excluded.pos3, pos4=excluded.pos4, updated_at=datetime('now')
  `).run(user_id, group_key, ...positions);
  res.json({ ok: true });
});

// ========================
// RESULTADOS GRUPOS
// ========================
app.get('/api/group-results', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM group_results').all();
  const result = {};
  rows.forEach(r => { result[r.group_key] = [r.pos1, r.pos2, r.pos3, r.pos4]; });
  res.json(result);
});

app.post('/api/group-results', requireAuth, (req, res) => {
  const { group_key, positions } = req.body;
  if (!group_key || !positions || positions.length !== 4) return res.status(400).json({ error: 'Datos incompletos' });
  db.prepare(`
    INSERT INTO group_results (group_key, pos1, pos2, pos3, pos4, updated_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(group_key) DO UPDATE SET
      pos1=excluded.pos1, pos2=excluded.pos2, pos3=excluded.pos3, pos4=excluded.pos4, updated_at=datetime('now')
  `).run(group_key, ...positions);
  res.json({ ok: true });
});

// ========================
// PREDICCIONES PREMIOS
// ========================
app.get('/api/award-predictions', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM award_predictions').all();
  const result = {};
  rows.forEach(r => {
    if (!result[r.user_id]) result[r.user_id] = {};
    result[r.user_id][r.award_id] = r.value;
  });
  res.json(result);
});

app.post('/api/award-predictions', requireAuth, (req, res) => {
  const { user_id, award_id, value } = req.body;
  if (req.user.id !== user_id) return res.status(403).json({ error: 'No podés editar predicciones de otro jugador' });
  if (!award_id) return res.status(400).json({ error: 'Datos incompletos' });
  db.prepare(`
    INSERT INTO award_predictions (user_id, award_id, value, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, award_id) DO UPDATE SET value=excluded.value, updated_at=datetime('now')
  `).run(user_id, award_id, value || '');
  res.json({ ok: true });
});

// ========================
// RESULTADOS PREMIOS
// ========================
app.get('/api/award-results', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM award_results').all();
  const result = {};
  rows.forEach(r => { result[r.award_id] = r.value; });
  res.json(result);
});

app.post('/api/award-results', requireAuth, (req, res) => {
  const { award_id, value } = req.body;
  if (!award_id) return res.status(400).json({ error: 'Datos incompletos' });
  db.prepare(`
    INSERT INTO award_results (award_id, value, updated_at)
    VALUES (?, ?, datetime('now'))
    ON CONFLICT(award_id) DO UPDATE SET value=excluded.value, updated_at=datetime('now')
  `).run(award_id, value || '');
  res.json({ ok: true });
});

// ========================
// START
// ========================
app.listen(PORT, () => {
  console.log(`🐓 Prode Mundial 2026 corriendo en puerto ${PORT}`);
});
