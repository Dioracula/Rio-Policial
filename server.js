'use strict';
// Policial da Cidade — servidor (contas + multiplayer)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'users.json');
const MAX_USERS = +process.env.MAX_USERS || 5000;
const NICK = /^[A-Za-z0-9_]{3,12}$/, MAXMSG = 8192, MAXROOM = 4, SESSION_MS = 30 * 864e5;
const LOOK_MAX = { skin: 8, hair: 5, hc: 8, glasses: 4, must: 3, beard: 4, fc: 8 };

function cleanLook(l) {
  const o = {}; l = l && typeof l === 'object' ? l : {};
  for (const k in LOOK_MAX) { const v = Math.floor(+l[k]); o[k] = v >= 0 && v < LOOK_MAX[k] ? v : (k === 'skin' ? 2 : 0); }
  return o;
}
const MISSIONS = ['roubo', 'homicídio', 'tráfico de drogas', 'banco', 'sequestro'];

const REDIS_URL = (process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/+$/, ''), REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const REMOTE = !!(REDIS_URL && REDIS_TOKEN);
const FLUSH_MS = REMOTE ? 10000 : 2000;
fs.mkdirSync(DATA_DIR, { recursive: true });
let db = { users: {}, sessions: {} };
const dirtyU = new Set(), dirtyS = new Set(), delS = new Set();
let anyDirty = false;
const touchUser = k => { dirtyU.add(k); anyDirty = true; };
const touchSession = h => { dirtyS.add(h); delS.delete(h); anyDirty = true; };
const dropSession = h => { delete db.sessions[h]; dirtyS.delete(h); delS.add(h); anyDirty = true; };

async function redis(cmds) {
  const r = await fetch(REDIS_URL + '/pipeline', {
    method: 'POST', headers: { Authorization: 'Bearer ' + REDIS_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmds), signal: AbortSignal.timeout(10000)
  });
  if (!r.ok) throw new Error('Redis HTTP ' + r.status);
  const out = await r.json();
  for (const o of out) if (o.error) throw new Error(o.error);
  return out.map(o => o.result);
}
function pairs(a) {
  const o = {};
  const ent = Array.isArray(a) ? Array.from({ length: a.length >> 1 }, (_, i) => [a[2 * i], a[2 * i + 1]]) : Object.entries(a || {});
  for (const [k, v] of ent) { try { o[k] = typeof v === 'string' ? JSON.parse(v) : v; } catch (e) {} }
  return o;
}
async function loadDb() {
  if (REMOTE) {
    const [u, s] = await redis([['HGETALL', 'pc:users'], ['HGETALL', 'pc:sessions']]);
    db.users = pairs(u); db.sessions = pairs(s);
  } else {
    try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); db.users = db.users || {}; db.sessions = db.sessions || {}; } catch (e) {}
  }
  console.log('Banco: ' + (REMOTE ? 'Upstash Redis' : 'arquivo ' + DB_FILE) + ' — ' + Object.keys(db.users).length + ' contas');
}
async function doFlush() {
  if (!anyDirty) return true;
  const us = [...dirtyU], ss = [...dirtyS], ds = [...delS];
  dirtyU.clear(); dirtyS.clear(); delS.clear(); anyDirty = false;
  try {
    if (REMOTE) {
      const cmds = [];
      for (const k of us) if (db.users[k]) cmds.push(['HSET', 'pc:users', k, JSON.stringify(db.users[k])]);
      for (const h of ss) if (db.sessions[h]) cmds.push(['HSET', 'pc:sessions', h, JSON.stringify(db.sessions[h])]);
      for (const h of ds) cmds.push(['HDEL', 'pc:sessions', h]);
      if (cmds.length) await redis(cmds);
    } else {
      const tmp = DB_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(db)); fs.renameSync(tmp, DB_FILE);
    }
    return true;
  } catch (e) {
    us.forEach(touchUser); ss.forEach(touchSession); ds.forEach(h => { delS.add(h); anyDirty = true; });
    return false;
  }
}
let chain = Promise.resolve();
const flush = () => (chain = chain.then(doFlush));
setInterval(flush, FLUSH_MS);

const now = () => Date.now();
const num = (v, a, b) => { v = +v; return Number.isFinite(v) ? Math.max(a, Math.min(b, v)) : 0; };
const int = (v, a, b) => Math.floor(num(v, a, b));
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const cleanCar = o => (!o || typeof o !== 'object') ? null : { x: +num(o.x, -2000, 2000).toFixed(2), z: +num(o.z, -2000, 2000).toFixed(2), r: +num(o.r, -10, 10).toFixed(2), hp: +num(o.hp, 0, 100).toFixed(2) };
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
  for (const [h, s] of Object.entries(db.sessions)) if (t - s.t > SESSION_MS) dropSession(h);
}, 60000);

// WebSocket
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

const online = new Map(), rooms = new Map(), invites = new Map();
function newSession(key) {
  const tok = crypto.randomBytes(24).toString('hex');
  db.sessions[sha(tok)] = { k: key, t: now() };
  const mine = Object.entries(db.sessions).filter(([, s]) => s.k === key).sort((a, b) => a[1].t - b[1].t);
  while (mine.length > 5) dropSession(mine.shift()[0]);
  touchSession(sha(tok)); return tok;
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
  const u = db.users[key]; u.last = now(); touchUser(key);
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
    if (!hits(ipHits, c.ip, 60000, 30)) return err('Muitas tentativas. Aguarde.');
    if (m.t === 'resume') {
      const tok = typeof m.token === 'string' ? m.token.slice(0, 100) : '';
      const s = db.sessions[sha(tok)];
      if (!s || now() - s.t > SESSION_MS || !db.users[s.k]) return err('Sessão expirada', { expired: true });
      if (now() - s.t > 864e5) { s.t = now(); touchSession(sha(tok)); }
      return login(c, s.k, tok);
    }
    const nick = String(m.nick || ''), pass = String(m.pass || '');
    if (!NICK.test(nick)) return err('Nick: 3–12 letras, números ou _');
    if (pass.length < 4 || pass.length > 40) return err('Senha: 4 a 40 caracteres');
    const key = nick.toLowerCase();
    if (m.t === 'reg') {
      if (db.users[key]) return err('Esse nick já está em uso');
      if (Object.keys(db.users).length >= MAX_USERS) return err('Servidor cheio');
      const salt = crypto.randomBytes(16).toString('hex'), hash = await hashPw(pass, salt);
      db.users[key] = { nick, salt, hash, friends: [], save: { score: 0, missionN: 0, money: 0, xp: 0, weps: [1,0,0,0], eq: 0, ammo: 0, arm: 0 }, created: now(), last: now() };
      touchUser(key);
      const tok = newSession(key);
      if (!(await flush())) { delete db.users[key]; dirtyU.delete(key); dropSession(sha(tok)); return err('Erro ao salvar conta.'); }
      return login(c, key, tok);
    }
    const f = fails.get(key), u = db.users[key], hash = await hashPw(pass, u ? u.salt : '0'.repeat(32));
    if (!u || !safeEq(hash, u.hash)) { fails.set(key, { n: (f ? f.n : 0) + 1, t: now() }); return err('Nick ou senha incorretos'); }
    fails.delete(key);
    return login(c, key, newSession(key));
  } finally { c.busy = false; }
}

function roomState(r) {
  const members = r.members.map(k => db.users[k].nick), looks = {}, xps = {};
  for (const k of r.members) { 
      const sv = db.users[k].save; 
      if (sv && sv.look) looks[db.users[k].nick] = sv.look; 
      xps[db.users[k].nick] = (sv && sv.xp) || 0;
  }
  const drv = r.driver && db.users[r.driver] ? db.users[r.driver].nick : '';
  const riders = (r.riders || [null, null, null]).map(k => (k && db.users[k]) ? db.users[k].nick : '');
  for (const k of r.members) { const c = online.get(k); if (c) c.send({ t: 'room', code: r.host, members, looks, xps, drv, riders, car: r.car || null }); }
}
function leaveRoom(c) {
  const me = c.user, r = rooms.get(c.room);
  c.room = null;
  if (!r || !me) return;
  if (r.hostKey === me) {
    rooms.delete(me);
    for (const k of r.members) { const x = online.get(k); if (x) { x.room = null; x.send({ t: 'room', code: '', members: [] }); } }
  } else {
    if (r.driver === me) r.driver = null;
    if (r.riders) { const idx = r.riders.indexOf(me); if (idx !== -1) r.riders[idx] = null; }
    r.members = r.members.filter(k => k !== me);
    c.send({ t: 'room', code: '', members: [] }); roomState(r);
  }
}
function handle(c, m) {
  const me = c.user, u = db.users[me], info = s => c.send({ t: 'info', s });
  switch (m.t) {
    case 'save': {
      const sv = { 
          score: int(m.score, -1e9, 1e9), missionN: int(m.missionN, 0, 1e6),
          money: int(m.money, 0, 1e9), xp: int(m.xp, 0, 1e9),
          weps: Array.isArray(m.weps) ? m.weps.map(x=>int(x,0,1)) : [1,0,0,0],
          eq: int(m.eq, 0, 3), ammo: int(m.ammo, 0, 1e6), arm: int(m.arm, 0, 100)
      };
      if (u.save.look) sv.look = u.save.look;
      const oldXp = u.save.xp || 0;
      u.save = sv; touchUser(me);
      if (Math.floor(Math.sqrt((oldXp)/50)) !== Math.floor(Math.sqrt(sv.xp/50))) {
        const r = rooms.get(c.room); if (r) roomState(r);
      }
      break;
    }
    case 'wipe': {
      const lk = u.save.look; u.save = { score: 0, missionN: 0, money: 0, xp: 0, weps: [1,0,0,0], eq: 0, ammo: 0, arm: 0 }; if (lk) u.save.look = lk; touchUser(me); break;
    }
    case 'look': { u.save.look = cleanLook(m.look); touchUser(me); const r = rooms.get(c.room); if (r) roomState(r); break; }
    case 'drive': {
      const r = rooms.get(c.room);
      if (!r) { if (m.on) c.send({ t: 'drv', ok: true }); break; }
      if (m.on) {
        if (r.driver && r.driver !== me && online.has(r.driver)) { c.send({ t: 'drv', ok: false }); info(db.users[r.driver].nick + ' já está dirigindo'); break; }
        if (r.riders) { const idx = r.riders.indexOf(me); if (idx !== -1) r.riders[idx] = null; }
        r.driver = me; c.send({ t: 'drv', ok: true }); roomState(r);
      } else if (r.driver === me) { r.driver = null; roomState(r); }
      break;
    }
    case 'ride': {
      const r = rooms.get(c.room);
      if (!r) { if (m.on) c.send({ t: 'ride', ok: false, err: 'Sem sala' }); break; }
      if (!r.riders) r.riders = [null, null, null];
      if (m.on) {
        if (r.driver === me) { c.send({ t: 'ride', ok: false, err: 'Você está dirigindo' }); break; }
        let idx = r.riders.indexOf(me);
        if (idx === -1) {
          idx = r.riders.indexOf(null);
          if (idx === -1) { c.send({ t: 'ride', ok: false, err: 'Viatura cheia (4/4)' }); break; }
          r.riders[idx] = me;
        }
        c.send({ t: 'ride', ok: true, seat: idx + 1 }); roomState(r);
      } else { const idx = r.riders.indexOf(me); if (idx !== -1) { r.riders[idx] = null; roomState(r); } }
      break;
    }
    case 'pres': {
      const r = rooms.get(c.room); if (!r) return;
      const t = now(); if (t - c.lp < 30) return; c.lp = t;
      const x = +num(m.x, -2000, 2000).toFixed(2), z = +num(m.z, -2000, 2000).toFixed(2), rr = +num(m.r, -10, 10).toFixed(2);
      const dr = r.driver === me && +m.d === 1;
      if (dr) { if (!r.car) r.car = {}; r.car.x = x; r.car.z = z; r.car.r = rr; r.car.hp = num(m.hp, 0, 100); }
      if (r.members.length < 2) return;
      const o = { t: 'pres', n: u.nick, x, z, r: rr, u: +num(m.u, -40, 40).toFixed(2), w: +num(m.w, -40, 40).toFixed(2), d: dr ? 1 : 0 };
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send(o); }
      break;
    }
    case 'clue':
    case 'end':
    case 'mis': {
      const r = rooms.get(c.room); if (!r) return;
      let out;
      if (m.t === 'clue') out = { t: 'clue', i: int(m.i, 0, 50) };
      else if (m.t === 'end') out = { t: 'end', text: String(m.text || '').slice(0, 140), pts: int(m.pts, -1000, 1000) };
      else out = { t: 'mis', from: u.nick, o: { t: m.o.t, s: int(m.o.s, 1, 3) || 1 }, sd: int(m.sd, 0, 1e9) };
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send(out); }
      break;
    }
    case 'logout': if (typeof m.token === 'string') dropSession(sha(m.token.slice(0, 100))); dropUser(c); break;
    case 'inv': {
      const tk = String(m.nick || '').toLowerCase();
      if (!NICK.test(tk) || tk === me) return info('Nick inválido');
      const tu = db.users[tk]; if (!tu) return info('Esse nick não existe');
      const tc = online.get(tk); if (!tc) return info(tu.nick + ' está offline');
      let r = rooms.get(c.room);
      if (!r) { r = { hostKey: me, host: u.nick, members: [me], driver: null, riders: [null, null, null], car: cleanCar(m.car) }; rooms.set(me, r); c.room = me; }
      if (r.members.includes(tk)) return info(tu.nick + ' já está na sala');
      if (r.members.length >= MAXROOM) return info('Sala cheia');
      invites.set(tk, { host: r.hostKey, t: now() }); tc.send({ t: 'invite', from: u.nick, host: r.host });
      roomState(r); info('Convite enviado para ' + tu.nick); break;
    }
    case 'acc': {
      const hk = String(m.host || '').toLowerCase(), iv = invites.get(me), r = rooms.get(hk);
      if (!iv || iv.host !== hk || now() - iv.t > 3e5) return info('Convite expirado');
      if (!r || !online.has(hk)) return info('A sala não existe mais');
      if (r.members.length >= MAXROOM) return info('Sala cheia');
      invites.delete(me); leaveRoom(c);
      r.members.push(me); c.room = hk; roomState(r);
      info('Você entrou na sala de ' + r.host); break;
    }
    case 'rej': invites.delete(me); break;
    case 'leave': leaveRoom(c); break;
    case 'fadd':
    case 'fdel': {
      const k = String(m.nick || '').toLowerCase();
      if (m.t === 'fadd') {
          const f = db.users[k]; if (!f) return info('Esse nick não existe');
          if (!u.friends.some(x => x.toLowerCase() === k) && u.friends.length < 50) { u.friends.push(f.nick); touchUser(me); info('Amigo adicionado'); }
      } else { u.friends = u.friends.filter(x => x.toLowerCase() !== k); touchUser(me); }
      c.send({ t: 'friends', list: friendList(me) }); break;
    }
  }
}

const server = http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  if (url === '/' || url === '/index.html') {
    fs.readFile(path.join(__dirname, 'index.html'), (e, b) => {
      if (e) { res.writeHead(500); return res.end('index.html não encontrado'); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      res.end(b);
    });
  } else { res.writeHead(404); res.end('404'); }
});
server.on('upgrade', (req, sock) => {
  const key = req.headers['sec-websocket-key'];
  if (String(req.headers.upgrade || '').toLowerCase() !== 'websocket' || !key) { sock.destroy(); return; }
  const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
  sock.write('HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: ' + accept + '

');
  sock.setNoDelay(true);
  new Conn(sock, req.socket.remoteAddress || '?');
});
loadDb().then(() => { server.listen(PORT, () => console.log('Servidor Policial da Cidade rodando na porta ' + PORT)); });
