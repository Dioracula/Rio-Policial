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
const LOOK_MAX = { skin: 8, hair: 7, hc: 8, glasses: 4, must: 3, beard: 4, fc: 8, sex: 2 };
function cleanLook(l) {
  const o = {}; l = l && typeof l === 'object' ? l : {};
  for (const k in LOOK_MAX) { const v = Math.floor(+l[k]); o[k] = v >= 0 && v < LOOK_MAX[k] ? v : (k === 'skin' ? 2 : 0); }
  return o;
}
const MISSIONS = ['roubo', 'homicídio', 'tráfico de drogas', 'banco', 'sequestro'];

// ---------- Armazenamento ----------
// Dois modos: (1) Upstash Redis via REST (grátis, sobrevive a reinícios; defina UPSTASH_REDIS_REST_URL e _TOKEN)
//             (2) arquivo JSON em DATA_DIR (padrão; no Render grátis o arquivo some quando reinicia)
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
    if (!Object.keys(db.users).length) { // migração única: importa o arquivo local, se houver
      try {
        const old = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
        if (old.users && Object.keys(old.users).length) {
          db.users = old.users; db.sessions = old.sessions || {};
          Object.keys(db.users).forEach(touchUser); Object.keys(db.sessions).forEach(touchSession);
          console.log('Contas importadas do arquivo local para o Redis.');
        }
      } catch (e) {}
    }
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
  } catch (e) { // devolve à fila para tentar de novo
    console.error('Erro ao salvar:', e.message);
    us.forEach(touchUser); ss.forEach(touchSession); ds.forEach(h => { delS.add(h); anyDirty = true; });
    return false;
  }
}
let chain = Promise.resolve();
const flush = () => (chain = chain.then(doFlush));
setInterval(flush, FLUSH_MS);
async function shutdown() { await Promise.race([flush(), new Promise(r => setTimeout(r, 4000))]); process.exit(0); }
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, shutdown);
process.on('uncaughtException', e => console.error('Erro não tratado:', e));
process.on('unhandledRejection', e => console.error('Promessa rejeitada:', e));

// ---------- Utilidades ----------
const now = () => Date.now();
const num = (v, a, b) => { v = +v; return Number.isFinite(v) ? Math.max(a, Math.min(b, v)) : 0; };
const int = (v, a, b) => Math.floor(num(v, a, b));
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const cleanCar = o => (!o || typeof o !== 'object') ? null : { x: +num(o.x, -2000, 2000).toFixed(2), z: +num(o.z, -2000, 2000).toFixed(2), r: +num(o.r, -10, 10).toFixed(2), h: o.h == null ? 100 : int(o.h, 0, 100) };
// Save do jogador: pontos, nível (xp), dinheiro, armas, munição, coletes e vida da viatura
function cleanSave(m) {
  const own = [...new Set((Array.isArray(m.own) ? m.own : [0]).map(x => int(x, 0, 9)))].slice(0, 12); if (!own.includes(0)) own.unshift(0);
  const ammo = {}; if (m.ammo && typeof m.ammo === 'object') for (let i = 1; i < 10; i++) if (m.ammo[i] != null && own.includes(i)) ammo[i] = int(m.ammo[i], 0, 999);
  const vests = {}; if (m.vests && typeof m.vests === 'object') for (let i = 0; i < 10; i++) if (m.vests[i] != null) { const d = int(m.vests[i], 0, 999); if (d > 0) vests[i] = d; }
  const eq = int(m.eq, 0, 9), vo = Math.floor(+m.vestOn);
  return { score: int(m.score, -1e9, 1e9), missionN: int(m.missionN, 0, 1e6), xp: int(m.xp, 0, 1e9), money: int(m.money, 0, 1e9), own, ammo, eq: own.includes(eq) ? eq : 0, vests, vestOn: vests[vo] != null ? vo : -1, carHp: int(m.carHp == null ? 100 : m.carHp, 0, 100), per: int(m.per, 0, 1e6), crm: int(m.crm, 0, 1e6) };
}
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
  for (const [h, s] of Object.entries(db.sessions)) if (t - s.t > SESSION_MS) dropSession(h);
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
    if (!hits(ipHits, c.ip, 60000, 30)) return err('Muitas tentativas. Aguarde um minuto.');
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
      if (!hits(regHits, c.ip, 36e5, 10)) return err('Muitas contas criadas daqui. Tente mais tarde.');
      if (db.users[key]) return err('Esse nick já está em uso');
      if (Object.keys(db.users).length >= MAX_USERS) return err('Servidor cheio');
      const salt = crypto.randomBytes(16).toString('hex'), hash = await hashPw(pass, salt);
      if (db.users[key]) return err('Esse nick já está em uso');
      db.users[key] = { nick, salt, hash, friends: [], save: { score: 0, missionN: 0 }, created: now(), last: now() };
      touchUser(key);
      const tok = newSession(key);
      if (!(await flush())) { // conta só vale se foi gravada de verdade
        delete db.users[key]; dirtyU.delete(key); dropSession(sha(tok));
        return err('Não consegui salvar a conta agora. Tente de novo em instantes.');
      }
      return login(c, key, tok);
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
  const members = r.members.map(k => db.users[k].nick), looks = {};
  for (const k of r.members) { const lk = db.users[k].save && db.users[k].save.look; if (lk) looks[db.users[k].nick] = lk; }
  const drv = r.driver && db.users[r.driver] ? db.users[r.driver].nick : '';
  const riders = (r.riders || [null, null, null]).map(k => (k && db.users[k]) ? db.users[k].nick : '');
  for (const k of r.members) { const c = online.get(k); if (c) c.send({ t: 'room', code: r.host, members, looks, drv, riders, car: r.car || null, tow: r.tow ? Math.max(0, Math.ceil((r.tow - now()) / 1000)) : 0 }); }
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
    c.send({ t: 'room', code: '', members: [] });
    roomState(r);
  }
}
function handle(c, m) {
  const me = c.user, u = db.users[me], info = s => c.send({ t: 'info', s });
  switch (m.t) {
    case 'save': {
      const sv = cleanSave(m);
      if (u.save.look) sv.look = u.save.look;
      if (JSON.stringify(sv) !== JSON.stringify(u.save)) { u.save = sv; touchUser(me); }
      break;
    }
    case 'wipe': {
      const lk = u.save.look; u.save = { score: 0, missionN: 0 }; if (lk) u.save.look = lk; touchUser(me); break;
    }
    case 'look': {
      u.save.look = cleanLook(m.look); touchUser(me);
      const r = rooms.get(c.room); if (r) roomState(r);
      break;
    }
    case 'drive': { // só um jogador por vez dirige a viatura da sala
      const r = rooms.get(c.room);
      if (!r) { if (m.on) c.send({ t: 'drv', ok: true }); break; }
      if (m.on) {
        if (r.driver && r.driver !== me && online.has(r.driver)) { c.send({ t: 'drv', ok: false }); info(db.users[r.driver].nick + ' já está dirigindo a viatura'); break; }
        if (r.riders) { const idx = r.riders.indexOf(me); if (idx !== -1) r.riders[idx] = null; }
        r.driver = me; c.send({ t: 'drv', ok: true }); roomState(r);
      } else if (r.driver === me) { r.driver = null; roomState(r); }
      break;
    }
    case 'ride': { // bancos de carona (até 3), só quem não está dirigindo
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
      } else {
        const idx = r.riders.indexOf(me);
        if (idx !== -1) { r.riders[idx] = null; roomState(r); }
      }
      break;
    }
    case 'clue': { // uma pista achada por um jogador vale para todos na sala
      const r = rooms.get(c.room); if (!r) return;
      const i = int(m.i, 0, 50);
      const out = { t: 'clue', i };
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send(out); }
      break;
    }
    case 'carhp': { // conserto da viatura vale para todos na sala
      const r = rooms.get(c.room); if (!r) return;
      const h = int(m.h, 0, 100); if (r.car) r.car.h = h;
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send({ t: 'carhp', h }); }
      break;
    }
    case 'gdmg': { // dano ao carro de fuga dos bandidos vale para todos na sala
      const r = rooms.get(c.room); if (!r) return;
      const out = { t: 'gdmg', d: int(m.d, 0, 100) };
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send(out); }
      break;
    }
    case 'arr': { // prisão: todos na sala veem o mesmo NPC detido (visual e dono da custódia)
      const r = rooms.get(c.room); if (!r) return;
      const tr = m.tr && typeof m.tr === 'object' ? m.tr : {};
      const out = { t: 'arr', by: u.nick, o: ['r', 'k', 's'].includes(m.o) ? m.o : 's', tr: { cor: String(tr.cor || '').slice(0, 12), bone: !!tr.bone, mochila: !!tr.mochila, altura: String(tr.altura || '').slice(0, 8) },
        pa: int(m.pa, 0, 0xffffff), sk: int(m.sk, 0, 0xffffff), hc: int(m.hc, 0, 0xffffff), lk: Array.isArray(m.lk) ? m.lk.slice(0, 8).map(v => int(v, 0, 9)) : null, x: +num(m.x, -2000, 2000).toFixed(1), z: +num(m.z, -2000, 2000).toFixed(1) };
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send(out); }
      break;
    }
    case 'dlv': { // entrega do preso na delegacia
      const r = rooms.get(c.room); if (!r) return;
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send({ t: 'dlv', by: u.nick }); }
      break;
    }
    case 'tow': { // reboque da viatura destruída: começa/termina para todos na sala
      const r = rooms.get(c.room); if (!r) return;
      let out;
      if (m.done) { r.tow = 0; r.car = { x: +num(m.x, -2000, 2000).toFixed(2), z: +num(m.z, -2000, 2000).toFixed(2), r: 0, h: int(m.h, 0, 100) }; out = { t: 'tow', done: 1 }; }
      else { const sec = int(m.sec, 5, 120); if (r.tow && r.tow > now()) return; r.tow = now() + sec * 1000; out = { t: 'tow', on: 1, sec }; }
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send(out); }
      break;
    }
    case 'talk': { // conversa com a vítima do roubo vale para todos na sala
      const r = rooms.get(c.room); if (!r) return;
      const out = { t: 'talk', i: int(m.i, 0, 7), zx: +num(m.zx, -2000, 2000).toFixed(1), zz: +num(m.zz, -2000, 2000).toFixed(1) };
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send(out); }
      break;
    }
    case 'end': { // conclusão de missão (vitória/derrota) vale para todos na sala
      const r = rooms.get(c.room); if (!r) return;
      const out = { t: 'end', text: String(m.text || '').slice(0, 140), pts: int(m.pts, -1000, 1000), w: m.w ? 1 : 0 };
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send(out); }
      break;
    }
    case 'faint': { // jogador desmaiou / foi socorrido: todos na sala veem
      const r = rooms.get(c.room); if (!r) return;
      const out = { t: 'faint', n: u.nick, on: m.on ? 1 : 0, x: +num(m.x, -2000, 2000).toFixed(1), z: +num(m.z, -2000, 2000).toFixed(1) };
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send(out); }
      break;
    }
    case 'amb': { // ambulância chamada para um jogador desmaiado da sala
      const r = rooms.get(c.room); if (!r) return;
      const who = String(m.who || '').toLowerCase();
      if (!NICK.test(who) || !r.members.includes(who)) return;
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send({ t: 'amb', who }); }
      break;
    }
    case 'svc': { // reforços chamados: a sala inteira vê a viatura e os policiais
      const r = rooms.get(c.room); if (!r || m.k !== 'ref') return;
      const t = now(); if (t - (c.lastSvc || 0) < 5000) return; c.lastSvc = t;
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send({ t: 'svc', k: 'ref', by: u.nick }); }
      break;
    }
    case 'pz': { // puzzle da cena do crime resolvido: a pista vale para todos na sala
      const r = rooms.get(c.room); if (!r) return;
      const out = { t: 'pz', i: int(m.i, -1, 7), u: String(m.u || '').slice(0, 5) };
      for (const k of r.members) if (k !== me) { const x = online.get(k); if (x) x.send(out); }
      break;
    }
    case 'logout':
      if (typeof m.token === 'string') dropSession(sha(m.token.slice(0, 100)));
      dropUser(c); break;
    case 'fadd': {
      const n = String(m.nick || ''), k = n.toLowerCase();
      if (!NICK.test(n) || k === me) return info('Nick inválido');
      const f = db.users[k]; if (!f) return info('Esse nick não existe');
      if (u.friends.length >= 50) return info('Lista de amigos cheia');
      if (!u.friends.some(x => x.toLowerCase() === k)) { u.friends.push(f.nick); touchUser(me); }
      c.send({ t: 'friends', list: friendList(me) }); info('Amigo adicionado: ' + f.nick); break;
    }
    case 'fdel': {
      const k = String(m.nick || '').toLowerCase();
      u.friends = u.friends.filter(x => x.toLowerCase() !== k); touchUser(me);
      c.send({ t: 'friends', list: friendList(me) }); break;
    }
    case 'inv': {
      const tk = String(m.nick || '').toLowerCase();
      if (!NICK.test(tk) || tk === me) return info('Nick inválido');
      const tu = db.users[tk]; if (!tu) return info('Esse nick não existe');
      const tc = online.get(tk); if (!tc) return info(tu.nick + ' está offline');
      let r = rooms.get(c.room);
      if (!r) { r = { hostKey: me, host: u.nick, members: [me], driver: null, riders: [null, null, null], car: cleanCar(m.car) }; rooms.set(me, r); c.room = me; }
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
      const r = rooms.get(c.room); if (!r) return;
      const t = now(); if (t - c.lp < 30) return; c.lp = t;
      const x = +num(m.x, -2000, 2000).toFixed(2), z = +num(m.z, -2000, 2000).toFixed(2), rr = +num(m.r, -10, 10).toFixed(2);
      const dr = r.driver === me && +m.d === 1;
      if (dr) r.car = { x, z, r: rr, h: int(m.h == null ? 100 : m.h, 0, 100) };
      if (r.members.length < 2) return;
      const o = { t: 'pres', n: u.nick, x, z, r: rr, u: +num(m.u, -40, 40).toFixed(2), w: +num(m.w, -40, 40).toFixed(2), d: dr ? 1 : 0, q: int(m.q, 0, 9), lv: int(m.lv, 0, 100), k: int(m.k, 0, 9) };
      if (dr) o.h = r.car.h;
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
  } else if (url === '/health') { res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify({ ok: true, jogadores_online: online.size, contas: Object.keys(db.users).length, banco: REMOTE ? 'redis' : 'arquivo' })); }
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
loadDb().then(() => {
  server.listen(PORT, () => console.log('Policial da Cidade rodando na porta ' + PORT));
  // Anti-sono: o servidor chama o próprio /health (Render define RENDER_EXTERNAL_URL sozinho).
  const SELF = (process.env.SELF_URL || process.env.RENDER_EXTERNAL_URL || '').replace(/\/+$/, '');
  if (SELF && process.env.KEEP_ALIVE !== '0') {
    setInterval(() => fetch(SELF + '/health', { signal: AbortSignal.timeout(15000) }).catch(() => {}), 9 * 60 * 1000);
    console.log('Anti-sono ligado: ' + SELF + '/health a cada 9 min');
  }
}).catch(e => { console.error('Falha ao abrir o banco (' + e.message + '). Verifique UPSTASH_REDIS_REST_URL/TOKEN.'); process.exit(1); });
