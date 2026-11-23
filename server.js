const express = require('express'), http = require('http'), crypto = require('crypto');
const fs = require('fs'), path = require('path');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');

const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const UP = path.join(DATA, 'uploads');
fs.mkdirSync(UP, { recursive: true });
const db = new Database(path.join(DATA, 'app.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, name TEXT, salt TEXT, hash TEXT);
CREATE TABLE IF NOT EXISTS tokens(token TEXT PRIMARY KEY, uid INTEGER);
CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY, frm INTEGER, to_ INTEGER, text TEXT, img TEXT, ts INTEGER, seen INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS msgs_pair ON msgs(frm, to_);`);

const app = express(), srv = http.createServer(app);
const io = new Server(srv, { cors: { origin: '*' } });
app.use((q, s, n) => {
  s.set({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Authorization,Content-Type', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' });
  q.method === 'OPTIONS' ? s.end() : n();
});
app.use(express.json());

const hash = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const userByToken = t => db.prepare('SELECT u.id,u.username,u.name FROM tokens t JOIN users u ON u.id=t.uid WHERE t.token=?').get(t || '');
const auth = (q, s, n) => {
  const u = userByToken((q.headers.authorization || '').slice(7));
  if (!u) return s.status(401).json({ error: 'Нужно войти' });
  q.user = u; n();
};
const issue = (s, id) => {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO tokens VALUES(?,?)').run(token, id);
  s.json({ token });
};

app.post('/api/register', (q, s) => {
  const { username, password, name } = q.body || {};
  const un = String(username || '').trim().toLowerCase();
  if (!/^[a-z0-9_]{3,20}$/.test(un)) return s.status(400).json({ error: 'Логин: 3–20 символов, латиница, цифры, _' });
  if (String(password || '').length < 6) return s.status(400).json({ error: 'Пароль: минимум 6 символов' });
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(un)) return s.status(409).json({ error: 'Этот логин уже занят' });
  const salt = crypto.randomBytes(16).toString('hex');
  const id = db.prepare('INSERT INTO users(username,name,salt,hash) VALUES(?,?,?,?)')
    .run(un, String(name || '').trim().slice(0, 40) || un, salt, hash(password, salt)).lastInsertRowid;
  issue(s, id);
});

app.post('/api/login', (q, s) => {
  const { username, password } = q.body || {};
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(username || '').trim().toLowerCase());
  const ok = u && crypto.timingSafeEqual(Buffer.from(hash(String(password || ''), u.salt)), Buffer.from(u.hash));
  if (!ok) return s.status(401).json({ error: 'Неверный логин или пароль' });
  issue(s, u.id);
});

app.get('/api/me', auth, (q, s) => s.json(q.user));

// ICE-серверы для звонков. TURN включается переменными окружения (см. README)
app.get('/api/ice', auth, (q, s) => {
  const iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
  if (process.env.TURN_URL) iceServers.push({ urls: process.env.TURN_URL.split(','), username: process.env.TURN_USER, credential: process.env.TURN_PASS });
  s.json({ iceServers });
});

app.get('/api/users', auth, (q, s) => {
  const like = '%' + String(q.query.q || '').replace(/[%_]/g, '') + '%';
  s.json(db.prepare('SELECT id,username,name FROM users WHERE id!=? AND (username LIKE ? OR name LIKE ?) LIMIT 20').all(q.user.id, like, like));
});

app.get('/api/chats', auth, (q, s) => {
  const me = q.user.id;
  s.json(db.prepare(`SELECT u.id,u.username,u.name,m.text,m.img,m.ts,m.frm,
    (SELECT COUNT(*) FROM msgs x WHERE x.frm=u.id AND x.to_=? AND x.seen=0) AS unread
    FROM users u JOIN msgs m ON m.id=(SELECT MAX(id) FROM msgs WHERE (frm=? AND to_=u.id) OR (frm=u.id AND to_=?))
    WHERE u.id!=? ORDER BY m.id DESC`).all(me, me, me, me));
});

app.get('/api/messages/:id', auth, (q, s) => {
  const me = q.user.id, other = +q.params.id;
  db.prepare('UPDATE msgs SET seen=1 WHERE frm=? AND to_=?').run(other, me);
  const u = db.prepare('SELECT id,username,name FROM users WHERE id=?').get(other);
  const msgs = db.prepare('SELECT id,frm,to_,text,img,ts FROM msgs WHERE (frm=? AND to_=?) OR (frm=? AND to_=?) ORDER BY id DESC LIMIT 200').all(me, other, other, me).reverse();
  s.json({ user: u, msgs });
});

// Картинки
const EXT = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif' };
const NAME = /^[a-f0-9]{32}\.(jpg|png|webp|gif)$/;
app.post('/api/upload', auth, express.raw({ type: Object.keys(EXT), limit: '15mb' }), (q, s) => {
  const ext = EXT[(q.headers['content-type'] || '').split(';')[0]];
  if (!ext || !Buffer.isBuffer(q.body) || !q.body.length) return s.status(400).json({ error: 'Нужна картинка JPG, PNG, WebP или GIF до 15 МБ' });
  const f = crypto.randomBytes(16).toString('hex') + '.' + ext;
  fs.writeFileSync(path.join(UP, f), q.body);
  s.json({ img: f });
});
app.get('/uploads/:f', (q, s) => {
  if (!NAME.test(q.params.f)) return s.sendStatus(404);
  const p = path.join(UP, q.params.f);
  if (!fs.existsSync(p)) return s.sendStatus(404);
  s.set({ 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'private, max-age=31536000, immutable' });
  q.query.dl ? s.download(p) : s.sendFile(p);
});

app.use(express.static(path.join(__dirname, 'www')));

// Сообщения и звонки в реальном времени
const online = new Map();
io.use((so, n) => {
  const u = userByToken(so.handshake.auth && so.handshake.auth.token);
  if (!u) return n(new Error('auth'));
  so.user = u; n();
});
io.on('connection', so => {
  const me = so.user.id;
  so.join('u' + me);
  online.set(me, (online.get(me) || 0) + 1);
  io.emit('presence', { id: me, on: 1 });
  so.emit('online', [...online.keys()]);

  so.on('msg', (d, ack) => {
    d = d || {};
    const to = +d.to, text = String(d.text || '').slice(0, 4000);
    const img = NAME.test(d.img || '') ? d.img : null;
    if (!to || (!text && !img) || !db.prepare('SELECT 1 FROM users WHERE id=?').get(to)) return ack && ack({ error: 1 });
    const ts = Date.now();
    const id = db.prepare('INSERT INTO msgs(frm,to_,text,img,ts) VALUES(?,?,?,?,?)').run(me, to, text, img, ts).lastInsertRowid;
    io.to('u' + me).to('u' + to).emit('msg', { id, frm: me, to_: to, text, img, ts });
    ack && ack({ ok: 1 });
  });
  so.on('seen', from => db.prepare('UPDATE msgs SET seen=1 WHERE frm=? AND to_=?').run(+from, me));

  ['offer', 'answer', 'ice', 'end'].forEach(ev =>
    so.on('call:' + ev, d => io.to('u' + +(d && d.to)).emit('call:' + ev, { ...d, from: me, name: so.user.name })));

  so.on('disconnect', () => {
    const c = (online.get(me) || 1) - 1;
    if (c) online.set(me, c); else { online.delete(me); io.emit('presence', { id: me, on: 0 }); }
  });
});

srv.listen(process.env.PORT || 3000, () => console.log('Сервер запущен'));
