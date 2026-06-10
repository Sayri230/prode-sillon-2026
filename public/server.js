const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'prode2026-secret';

const dbDir = path.join(__dirname, 'db');
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir);
const db = new DatabaseSync(path.join(dbDir, 'prode.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    match_id TEXT NOT NULL,
    h1 INTEGER, a1 INTEGER, ya INTEGER, yb INTEGER, ca INTEGER, cb INTEGER,
    locked INTEGER DEFAULT 0,
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, match_id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS results (
    match_id TEXT PRIMARY KEY,
    h1 INTEGER, a1 INTEGER, ya INTEGER, yb INTEGER, ca INTEGER, cb INTEGER,
    updated_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS top_scorers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    match_date TEXT NOT NULL,
    player_name TEXT NOT NULL,
    locked INTEGER DEFAULT 0,
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, match_date),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS top_scorer_results (
    match_date TEXT PRIMARY KEY,
    player_name TEXT NOT NULL,
    goals INTEGER NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
  );
`);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'No autorizado' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Solo admins' });
    next();
  });
}

function calcScore(pred, result) {
  if (!result || result.h1 === null) return null;
  let pts = 0;
  if (pred.h1 !== null && pred.a1 !== null) {
    const predSign = Math.sign(pred.h1 - pred.a1);
    const resSign = Math.sign(result.h1 - result.a1);
    if (predSign === resSign) { pts += 3; if (pred.h1 === result.h1 && pred.a1 === result.a1) pts += 3; }
  }
  if (pred.ya !== null && pred.yb !== null && result.ya !== null) {
    const predSign = Math.sign(pred.ya - pred.yb);
    const resSign = Math.sign(result.ya - result.yb);
    if (predSign === resSign) { pts += 2; if (pred.ya === result.ya && pred.yb === result.yb) pts += 2; }
  }
  if (pred.ca !== null && pred.cb !== null && result.ca !== null) {
    const predSign = Math.sign(pred.ca - pred.cb);
    const resSign = Math.sign(result.ca - result.cb);
    if (predSign === resSign) { pts += 2; if (pred.ca === result.ca && pred.cb === result.cb) pts += 2; }
  }
  return pts;
}

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });
  if (username.trim().length < 2) return res.status(400).json({ error: 'Nombre muy corto' });
  if (password.length < 6) return res.status(400).json({ error: 'Contraseña muy corta (mín 6 caracteres)' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    const stmt = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
    const result = stmt.run(username.trim(), hash);
    const token = jwt.sign({ id: result.lastInsertRowid, username: username.trim(), isAdmin: false }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username: username.trim() });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'Ese nombre ya existe' });
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  const token = jwt.sign({ id: user.id, username: user.username, isAdmin: user.is_admin === 1 }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username, isAdmin: user.is_admin === 1 });
});

app.get('/api/predictions', authMiddleware, (req, res) => {
  const preds = db.prepare('SELECT * FROM predictions WHERE user_id = ?').all(req.user.id);
  const map = {};
  preds.forEach(p => { map[p.match_id] = p; });
  res.json(map);
});

app.post('/api/predictions/:matchId', authMiddleware, (req, res) => {
  const { matchId } = req.params;
  const { h1, a1, ya, yb, ca, cb } = req.body;
  const existing = db.prepare('SELECT locked FROM predictions WHERE user_id = ? AND match_id = ?').get(req.user.id, matchId);
  if (existing && existing.locked) return res.status(403).json({ error: 'Partido cerrado' });
  db.prepare(`INSERT INTO predictions (user_id, match_id, h1, a1, ya, yb, ca, cb, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, match_id) DO UPDATE SET
    h1=excluded.h1, a1=excluded.a1, ya=excluded.ya, yb=excluded.yb,
    ca=excluded.ca, cb=excluded.cb, updated_at=excluded.updated_at
  `).run(req.user.id, matchId, h1, a1, ya, yb, ca, cb);
  res.json({ ok: true });
});

app.post('/api/topscorer/:date', authMiddleware, (req, res) => {
  const { date } = req.params;
  const { player_name } = req.body;
  if (!player_name || player_name.trim().length < 2) return res.status(400).json({ error: 'Nombre inválido' });
  const existing = db.prepare('SELECT locked FROM top_scorers WHERE user_id = ? AND match_date = ?').get(req.user.id, date);
  if (existing && existing.locked) return res.status(403).json({ error: 'Ya no podés cambiar el goleador' });
  db.prepare(`INSERT INTO top_scorers (user_id, match_date, player_name, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, match_date) DO UPDATE SET
    player_name=excluded.player_name, updated_at=excluded.updated_at
  `).run(req.user.id, date, player_name.trim());
  res.json({ ok: true });
});

app.get('/api/topscorer/:date', authMiddleware, (req, res) => {
  const { date } = req.params;
  const pick = db.prepare('SELECT * FROM top_scorers WHERE user_id = ? AND match_date = ?').get(req.user.id, date);
  res.json(pick || null);
});

app.get('/api/scores/me', authMiddleware, (req, res) => {
  const preds = db.prepare('SELECT * FROM predictions WHERE user_id = ?').all(req.user.id);
  const results = db.prepare('SELECT * FROM results').all();
  const resultMap = {};
  results.forEach(r => { resultMap[r.match_id] = r; });
  let total = 0;
  const breakdown = {};
  preds.forEach(p => {
    const pts = calcScore(p, resultMap[p.match_id]);
    if (pts !== null) { total += pts; breakdown[p.match_id] = pts; }
  });
  const scorerPicks = db.prepare('SELECT * FROM top_scorers WHERE user_id = ?').all(req.user.id);
  const scorerResults = db.prepare('SELECT * FROM top_scorer_results').all();
  const scorerResultMap = {};
  scorerResults.forEach(r => { scorerResultMap[r.match_date] = r; });
  let scorerPts = 0;
  scorerPicks.forEach(pick => {
    const result = scorerResultMap[pick.match_date];
    if (result && result.player_name.toLowerCase() === pick.player_name.toLowerCase()) scorerPts += 3;
  });
  res.json({ total: total + scorerPts, matchBreakdown: breakdown, scorerPoints: scorerPts });
});

app.get('/api/leaderboard', authMiddleware, (req, res) => {
  const users = db.prepare('SELECT id, username FROM users').all();
  const allPreds = db.prepare('SELECT * FROM predictions').all();
  const allResults = db.prepare('SELECT * FROM results').all();
  const allScorerPicks = db.prepare('SELECT * FROM top_scorers').all();
  const allScorerResults = db.prepare('SELECT * FROM top_scorer_results').all();
  const resultMap = {};
  allResults.forEach(r => { resultMap[r.match_id] = r; });
  const scorerResultMap = {};
  allScorerResults.forEach(r => { scorerResultMap[r.match_date] = r; });
  const scores = users.map(u => {
    const preds = allPreds.filter(p => p.user_id === u.id);
    let total = 0;
    preds.forEach(p => { const pts = calcScore(p, resultMap[p.match_id]); if (pts !== null) total += pts; });
    allScorerPicks.filter(p => p.user_id === u.id).forEach(pick => {
      const result = scorerResultMap[pick.match_date];
      if (result && result.player_name.toLowerCase() === pick.player_name.toLowerCase()) total += 3;
    });
    return { username: u.username, score: total, predictions: preds.length };
  });
  scores.sort((a, b) => b.score - a.score);
  res.json(scores);
});

app.post('/api/admin/result/:matchId', adminMiddleware, (req, res) => {
  const { matchId } = req.params;
  const { h1, a1, ya, yb, ca, cb } = req.body;
  db.prepare(`INSERT INTO results (match_id, h1, a1, ya, yb, ca, cb, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(match_id) DO UPDATE SET
    h1=excluded.h1, a1=excluded.a1, ya=excluded.ya, yb=excluded.yb,
    ca=excluded.ca, cb=excluded.cb, updated_at=excluded.updated_at
  `).run(matchId, h1, a1, ya, yb, ca, cb);
  db.prepare('UPDATE predictions SET locked=1 WHERE match_id=?').run(matchId);
  res.json({ ok: true });
});

app.post('/api/admin/topscorer/:date', adminMiddleware, (req, res) => {
  const { date } = req.params;
  const { player_name, goals } = req.body;
  db.prepare(`INSERT INTO top_scorer_results (match_date, player_name, goals, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(match_date) DO UPDATE SET
    player_name=excluded.player_name, goals=excluded.goals, updated_at=excluded.updated_at
  `).run(date, player_name, goals);
  db.prepare('UPDATE top_scorers SET locked=1 WHERE match_date=?').run(date);
  res.json({ ok: true });
});

app.post('/api/admin/make-admin', (req, res) => {
  const { secret, username } = req.body;
  if (secret !== process.env.ADMIN_SECRET && secret !== 'prode-admin-setup-2026')
    return res.status(403).json({ error: 'Clave incorrecta' });
  const user = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  db.prepare('UPDATE users SET is_admin=1 WHERE username=?').run(username);
  res.json({ ok: true, message: `${username} ahora es admin. Volvé a loguearte.` });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Prode 2026 corriendo en http://localhost:${PORT}`));
