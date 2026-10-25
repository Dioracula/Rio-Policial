'use strict';
// Policial da Cidade — servidor (contas + multiplayer). Sem dependências: só Node 18+.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'users.json');
const MAX_USERS = +process.env.MAX_USERS || 5000;
const NICK = /^[A-Za-z0-9_]{3,12}$/, MAXMSG = 8192, MAXROOM = 4, SESSION_MS = 30 * 864e5;
const MISSIONS = ['roubo', 'homicídio', 'tráfico de drogas', 'banco', 'sequestro'];

// ---------- Armazenamento (arquivo JSON, gravação atômica) ----------
fs.mkdirSync(DATA_DIR, { recursive: true });
let db = { users: {}, sessions: {} };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); db.users = db.users || {}; db.sessions = db.sessions || {}; } catch (e) {}
let dirty = false;
const persist = () => { dirty = true; };
function flush() {
  if (!dirty) return; dirty = false;
  const tmp = DB_FILE + '.tmp';
  try { fs.writeFileSync(tmp, JSON.stringify(db)); fs.renameSync(tmp, DB_FILE); } catch (e) { console.error('Erro ao salvar:', e.message); }
}
setInterval(flush, 2000);
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => { flush(); process.exit(0); });

// ---------- Utilidades ----------
const now = () => Date.now();
const num = (v, a, b) => { v = +v; return Number.isFinite(v) ? Math.max(a, Math.min(b, v)) : 0; };
const int = (v, a, b) => Math.floor(num(v, a, b));
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const hashPw = async (p, salt) => (await scrypt(p, salt, 64)).toString('hex');
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
function hits(map, key, windowMs, max) {
  const t = now(), a = (map.get(key) || []).filter(x => t - x < windowMs);
  a.push(t); map.set(key, a); return a.length <= max;
}
const ipHits = new Map(), regHits = new Map(), fails = new Map();
setInterval(() => {
  const t = now();
  for (const [k, a] of ipHits) if (!a.length || t - a[a.length - 1] > 6e4) ipHits.delete(k);
  for (const [k, a] of regHits) if (!a.length || t - a[a.length - 1] > 36e5) regHits.delete(k);
  for (const [k, f] of fails) if (t - f.t > 6e5) fails.delete(k);
  for (const [k, i] of invites) if (t - i.t > 3e5) invites.delete(k);
  for (const [h, s] of Object.entries(db.sessions)) if (t - s.t > SESSION_MS) { delete db.sessions[h]; persist(); }
}, 60000);

// ---------- WebSocket mínimo (RFC 6455) ----------
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
function frame(op, pl) {
  const l = pl.length; let h;
  if (l < 126) h = Buffer.from([128 | op, l]);
  else if (l < 65536) { h = Buffer.alloc(4); h[0] = 128 | op; h[1] = 126; h.writeUInt16BE(l, 2); }
  else { h = Buffer.alloc(10); h[0] = 128 | op; h[1] = 127; h.writeUInt32BE(l, 6); }
  return Buffer.concat([h, pl]);
}
const conns = new Set();
class Conn {
  constructor(sock, ip) {
    this.sock = sock; this.ip = ip; this.buf = Buffer.alloc(0); this.frag = null; this.fragLen = 0;
    this.user = null; this.room = null; this.alive = true; this.cnt = 0; this.busy = false; this.lp = 0; this.lm = 0;
    conns.add(this);
    sock.on('data', d => this.onData(d));
    sock.on('close', () => this.onClose());
    sock.on('error', () => {});
  }
  send(o) {
    const s = this.sock;
    if (!s.writable || s.destroyed) return;
    if (s.writableLength > 1e6) return this.kill();
    s.write(frame(1, Buffer.from(JSON.stringify(o))));
  }
  close() { try { this.sock.end(frame(8, Buffer.alloc(0))); } catch (e) {} }
  kill() { try { this.sock.destroy(); } catch (e) {} }
  onClose() { dropUser(this); conns.delete(this); }
  onData(d) {
    this.alive = true;
    this.buf = Buffer.concat([this.buf, d]);
    if (this.buf.length > MAXMSG * 4) return this.kill();
    for (;;) {
      const b = this.buf; if (b.length < 2) return;
      const fin = !!(b[0] & 128), op = b[0] & 15, masked = !!(b[1] & 128);
      let len = b[1] & 127, off = 2;
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (b.length < 10) return; if (b.readUInt32BE(2)) return this.kill(); len = b.readUInt32BE(6); off = 10; }
      if (!masked || len > MAXMSG) return this.kill();
      if (b.length < off + 4 + len) return;
      const mask = b.subarray(off, off + 4), pl = Buffer.from(b.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < len; i++) pl[i] ^= mask[i & 3];
      this.buf = b.subarray(off + 4 + len);
      if (op === 8) { this.close(); return; }
      if (op === 9) { this.sock.write(frame(10, pl)); continue; }
      if (op === 10) continue;
      if (op === 1 || op === 2) { this.frag = []; this.fragLen = 0; }
      else if (op !== 0 || !this.frag) return this.kill();
      this.frag.push(pl); this.fragLen += len;
      if (this.fragLen > MAXMSG) return this.kill();
      if (fin) { const full = Buffer.concat(this.frag).toString('utf8'); this.frag = null; this.onText(full); }
    }
  }
  onText(s) {
    if (++this.cnt > 80) return this.kill();
    let m; try { m = JSON.parse(s); } catch (e) { return; }
    if (!m || typeof m !== 'object' || typeof m.t !== 'string') return;
    if (m.t === 'reg' || m.t === 'login' || m.t === 'resume') return void doAuth(this, m);
    if (!this.user) return;
    handle(this, m);
  }
}
setInterval(() => { for (const c of conns) c.cnt = 0; }, 1000);
setInterval(() => {
  for (const c of conns) {
    if (!c.alive) { c.kill(); continue; }
    c.alive = false;
    try { c.sock.write(frame(9, Buffer.alloc(0))); } catch (e) {}
  }
}, 25000);

// ---------- Contas ----------
const online = new Map(), rooms = new Map(), invites = new Map();
function newSession(key) {
  const tok = crypto.randomBytes(24).toString('hex');
  db.sessions[sha(tok)] = { k: key, t: now() };
  const mine = Object.entries(db.sessions).filter(([, s]) => s.k === key).sort((a, b) => a[1].t - b[1].t);
  while (mine.length > 5) delete db.sessions[mine.shift()[0]];
  persist(); return tok;
}
const friendList = key => db.users[key].friends.map(n => ({ n, on: online.has(n.toLowerCase()) }));
function notifyFriends(key) {
  for (const [k, c] of online) {
    if (k !== key && db.users[k].friends.some(f => f.toLowerCase() === key)) c.send({ t: 'friends', list: friendList(k) });
  }
}
function login(c, key, token) {
  if (c.user) dropUser(c);
  const old = online.get(key);
  if (old && old !== c) { old.send({ t: 'kicked' }); dropUser(old); old.close(); }
  c.user = key; online.set(key, c);
  const u = db.users[key];
  c.send({ t: 'auth', ok: true, token, nick: u.nick, friends: friendList(key), save: u.save });
  notifyFriends(key);
}
function dropUser(c) {
  if (!c.user) return;
  const key = c.user;
  leaveRoom(c);
  if (online.get(key) === c) online.delete(key);
  c.user = null;
  notifyFriends(key);
}
async function doAuth(c, m) {
  if (c.busy) return; c.busy = true;
  const err = (e, extra) => c.send(Object.assign({ t: 'auth', ok: false, err: e }, extra));
  try {
    if (!hits(ipHits, c.ip, 60000, 30)) return err('Muitas tentativas. Aguarde um minuto.');
    if (m.t === 'resume') {
      const tok = typeof m.token === 'string' ? m.token.slice(0, 100) : '';
      const s = db.sessions[sha(tok)];
      if (!s || now() - s.t > SESSION_MS || !db.users[s.k]) return err('Sessão expirada', { expired: true });
      s.t = now(); persist();
      return login(c, s.k, tok);
    }
    const nick = String(m.nick || ''), pass = String(m.pass || '');
    if (!NICK.test(nick)) return err('Nick: 3–12 letras, números ou _');
    if (pass.length < 4 || pass.length > 40) return err('Senha: 4 a 40 caracteres');
    const key = nick.toLowerCase();
    if (m.t === 'reg') {
      if (!hits(regHits, c.ip, 36e5, 10)) return err('Muitas contas criadas daqui. Tente mais tarde.');
      if (db.users[key]) return err('Esse nick já está em uso');
      if (Object.keys(db.users).length >= MAX_USERS) return err('Servidor cheio');
      const salt = crypto.randomBytes(16).toString('hex'), hash = await hashPw(pass, salt);
      if (db.users[key]) return err('Esse nick já está em uso');
      db.users[key] = { nick, salt, hash, friends: [], save: { score: 0, missionN: 0 }, created: now() };
      persist();
      return login(c, key, newSession(key));
    }
    const f = fails.get(key);
    if (f && f.n >= 8 && now() - f.t < 6e5) return err('Conta bloqueada por alguns minutos (muitas tentativas)');
    const u = db.users[key];
    const hash = await hashPw(pass, u ? u.salt : '0'.repeat(32));
    if (!u || !safeEq(hash, u.hash)) {
      fails.set(key, { n: (f && now() - f.t < 6e5 ? f.n : 0) + 1, t: now() });
      return err('Nick ou senha incorretos');
    }
    fails.delete(key);
    return login(c, key, newSession(key));
  } finally { c.busy = false; }
}

// ---------- Salas ----------
function roomState(r) {
  const members = r.members.map(k => db.users[k].nick);
  for (const k of r.members) { const c = online.get(k); if (c) c.send({ t: 'room', code: r.host, members }); }
}
function leaveRoom(c) {
  const me = c.user, r = rooms.get(c.room);
  c.room = null;
  if (!r || !me) return;
  if (r.hostKey === me) {
    rooms.delete(me);
    for (const k of r.members) { const x = online.get(k); if (x) { x.room = null; x.send({ t: 'room', code: '', members: [] }); } }
  } else {
    r.members = r.members.filter(k => k !== me);
    c.send({ t: 'room', code: '', members: [] });
    roomState(r);
  }
}
function handle(c, m) {
  const me = c.user, u = db.users[me], info = s => c.send({ t: 'info', s });
  switch (m.t) {
    case 'save':
      u.save = { score: int(m.score, -1e9, 1e9), missionN: int(m.missionN, 0, 1e6) }; persist(); break;
    case 'wipe':
      u.save = { score: 0, missionN: 0 }; persist(); break;
    case 'logout':
      if (typeof m.token === 'string') { delete db.sessions[sha(m.token.slice(0, 100))]; persist(); }
      dropUser(c); break;
    case 'fadd': {
      const n = String(m.nick || ''), k = n.toLowerCase();
      if (!NICK.test(n) || k === me) return info('Nick inválido');
      const f = db.users[k]; if (!f) return info('Esse nick não existe');
      if (u.friends.length >= 50) return info('Lista de amigos cheia');
      if (!u.friends.some(x => x.toLowerCase() === k)) { u.friends.push(f.nick); persist(); }
      c.send({ t: 'friends', list: friendList(me) }); info('Amigo adicionado: ' + f.nick); break;
    }
    case 'fdel': {
      const k = String(m.nick || '').toLowerCase();
      u.friends = u.friends.filter(x => x.toLowerCase() !== k); persist();
      c.send({ t: 'friends', list: friendList(me) }); break;
    }
    case 'inv': {
      const tk = String(m.nick || '').toLowerCase();
      if (!NICK.test(tk) || tk === me) return info('Nick inválido');
      const tu = db.users[tk]; if (!tu) return info('Esse nick não existe');
      const tc = online.get(tk); if (!tc) return info(tu.nick + ' está offline');
      let r = rooms.get(c.room);
      if (!r) { r = { hostKey: me, host: u.nick, members: [me] }; rooms.set(me, r); c.room = me; }
      if (r.members.includes(tk)) return info(tu.nick + ' já está na sala');
      if (r.members.length >= MAXROOM) return info('Sala cheia (4/4)');
      invites.set(tk, { host: r.hostKey, t: now() });
      tc.send({ t: 'invite', from: u.nick, host: r.host });
      roomState(r); info('Convite enviado para ' + tu.nick); break;
    }
    case 'rej': invites.delete(me); break;
    case 'acc': {
      const hk = String(m.host || '').toLowerCase(), iv = invites.get(me), r = rooms.get(hk);
      if (!iv || iv.host !== hk || now() - iv.t > 3e5) return info('Convite expirado');
      if (!r || !online.has(hk)) return info('A sala não existe mais');
      if (r.members.length >= MAXROOM) return info('Sala cheia (4/4)');
      invites.delete(me);
      leaveRoom(c);
      r.members.push(me); c.room = hk; roomState(r);
      info('Você entrou na sala de ' + r.host); break;
    }
    case 'leave': leaveRoom(c); break;
    case 'pres': {
      const r = rooms.get(c.room); if (!r || r.members.length < 2) return;
      const t = now(); if (t - c.lp < 50) return; c.lp = t;
      const o = { t: 'pres', n: u.nick, x: +num(m.x, -2000, 2000).toFixed(2), z: +num(m.z, -2000, 2000).toFixed(2), r: +num(m.r, -10, 10).toFixed(2) };
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send(o); }
      break;
    }
    case 'mis': {
      const r = rooms.get(c.room); if (!r) return;
      const t = now(); if (t - c.lm < 1000) return; c.lm = t;
      const o = m.o || {}; if (!MISSIONS.includes(o.t)) return;
      const out = { t: 'mis', from: u.nick, o: { t: o.t, s: int(o.s, 1, 3) || 1 }, sd: int(m.sd, 0, 1e9) };
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send(out); }
      break;
    }
  }
}

// ---------- HTTP ----------
const server = http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  if (url === '/' || url === '/index.html') {
    fs.readFile(path.join(__dirname, 'index.html'), (e, b) => {
      if (e) { res.writeHead(500); return res.end('index.html não encontrado'); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff' });
      res.end(b);
    });
  } else if (url === '/health') { res.writeHead(200); res.end('ok'); }
  else { res.writeHead(404); res.end('404'); }
});
server.on('upgrade', (req, sock) => {
  const key = req.headers['sec-websocket-key'];
  if (String(req.headers.upgrade || '').toLowerCase() !== 'websocket' || !key) { sock.destroy(); return; }
  const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  sock.setNoDelay(true);
  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?';
  new Conn(sock, ip);
});
server.listen(PORT, () => console.log('Policial da Cidade rodando na porta ' + PORT + ' (dados em ' + DATA_DIR + ')'));
