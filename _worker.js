// Arcade Hub backend for Cloudflare Pages (advanced mode). Needs one D1 binding named DB.
// Admin login: user "lunarsage". Password is read from the ADMIN_PASSWORD env var if set,
// otherwise the default below is used. This file is never served to visitors.
const ADMIN = 'lunarsage';
const DEFAULT_ADMIN_PW = 'Stargate.sg23';

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const rid = () => hex(crypto.getRandomValues(new Uint8Array(16)));
const clean = n => String(n || '').replace(/[<>&"']/g, '').trim().slice(0, 14);
const enc = s => new TextEncoder().encode(s);
async function hash(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc(salt), iterations: 100000, hash: 'SHA-256' }, k, 256));
}
const same = (a, b) => { a = String(a); b = String(b); let d = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return d === 0; };

let ready;
const SCHEMA = [
  'CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT,salt TEXT,hash TEXT,money INT DEFAULT 0,data TEXT,t INT)',
  'CREATE TABLE IF NOT EXISTS sess(tok TEXT PRIMARY KEY,uid TEXT)',
  'CREATE TABLE IF NOT EXISTS lb(g TEXT,uid TEXT,name TEXT,score INT,t INT,PRIMARY KEY(g,uid))',
  'CREATE TABLE IF NOT EXISTS notif(id INTEGER PRIMARY KEY AUTOINCREMENT,uid TEXT,txt TEXT,t INT)',
  'CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,type TEXT,t INT)'
];

async function api(req, env, p, u) {
  const DB = env.DB;
  if (!DB) return J({ error: 'No D1 database bound. Add a D1 binding named DB in Pages > Settings > Bindings.' }, 500);
  await (ready ??= DB.batch(SCHEMA.map(s => DB.prepare(s))));
  const b = req.method === 'POST' ? await req.json().catch(() => ({})) : {};
  const tok = (req.headers.get('Authorization') || '').slice(7);
  const s = tok && await DB.prepare('SELECT uid FROM sess WHERE tok=?').bind(tok).first();
  const uid = s && s.uid, now = Date.now();
  const mk = async id => { const t = rid(); await DB.prepare('INSERT INTO sess VALUES(?,?)').bind(t, id).run(); return t; };
  const log = (n, t) => DB.prepare('INSERT INTO log(name,type,t) VALUES(?,?,?)').bind(n, t, now).run();

  if (p === 'board') {
    const g = u.searchParams.get('g') || '';
    const r = g === 'money'
      ? await DB.prepare('SELECT id,name,money v FROM users WHERE money>0 ORDER BY money DESC LIMIT 10').all()
      : await DB.prepare('SELECT uid id,name,score v FROM lb WHERE g=? ORDER BY score DESC LIMIT 10').bind(g).all();
    return J(r.results);
  }
  if (p === 'guest') {
    const n = clean(b.name) || 'Player';
    if (n.toLowerCase() === ADMIN) return J({ error: 'That name is reserved.' }, 400);
    if (uid && uid !== 'admin') {
      await DB.prepare('UPDATE users SET name=? WHERE id=? AND salt IS NULL').bind(n, uid).run();
      return J({ token: tok, uid });
    }
    const id = rid();
    await DB.prepare('INSERT INTO users(id,name,money,t) VALUES(?,?,0,?)').bind(id, n, now).run();
    await log(n, 'guest');
    return J({ token: await mk(id), uid: id });
  }
  if (p === 'signup' || p === 'login') {
    const n = String(b.name || ''), pw = String(b.pw || '');
    if (!/^[A-Za-z0-9_]{3,14}$/.test(n)) return J({ error: 'Username: 3-14 letters, numbers or _' }, 400);
    if (n.toLowerCase() === ADMIN) return J({ error: 'That username is reserved.' }, 400);
    if (pw.length < 6) return J({ error: 'Password must be 6+ characters.' }, 400);
    const row = await DB.prepare('SELECT * FROM users WHERE lower(name)=lower(?) AND salt IS NOT NULL').bind(n).first();
    if (p === 'signup') {
      if (row) return J({ error: 'That username is taken.' }, 400);
      const id = rid(), salt = rid();
      await DB.prepare('INSERT INTO users(id,name,salt,hash,money,t) VALUES(?,?,?,?,0,?)').bind(id, n, salt, await hash(pw, salt), now).run();
      await log(n, 'signup');
      return J({ token: await mk(id), uid: id, name: n });
    }
    if (!row || !same(await hash(pw, row.salt), row.hash)) return J({ error: 'Wrong username or password.' }, 401);
    await log(row.name, 'login');
    return J({ token: await mk(row.id), uid: row.id, name: row.name, data: row.data });
  }
  if (p === 'admin') {
    const okPw = same(b.pw || '', env.ADMIN_PASSWORD || DEFAULT_ADMIN_PW);
    if (String(b.name || '').trim().toLowerCase() !== ADMIN || !okPw) return J({ error: 'Wrong username or password.' }, 401);
    return J({ token: await mk('admin') });
  }
  if (p === 'admin/data' || p === 'admin/del') {
    if (uid !== 'admin') return J({ error: 'Not allowed.' }, 403);
    if (p === 'admin/del') {
      const id = String(b.id || '');
      await DB.batch(['DELETE FROM users WHERE id=?', 'DELETE FROM lb WHERE uid=?', 'DELETE FROM sess WHERE uid=?', 'DELETE FROM notif WHERE uid=?'].map(q => DB.prepare(q).bind(id)));
      return J({ ok: 1 });
    }
    const log_ = (await DB.prepare('SELECT name,type,t FROM log ORDER BY id DESC LIMIT 300').all()).results;
    const users = (await DB.prepare('SELECT id,name,money,t,data,salt IS NOT NULL acct FROM users ORDER BY money DESC LIMIT 500').all()).results;
    return J({ log: log_, users });
  }

  if (!uid || uid === 'admin') return J({ error: 'Not signed in.' }, 401);
  if (p === 'sync') {
    await DB.prepare('UPDATE users SET money=?,data=?,t=? WHERE id=?').bind(Math.max(0, Math.floor(+b.money || 0)), String(b.data || '').slice(0, 60000), now, uid).run();
    return J({ ok: 1 });
  }
  if (p === 'score') {
    const g = String(b.game || '').slice(0, 40), sc = Math.floor(+b.score);
    if (!g || !(sc > 0) || sc > 1e9) return J({ error: 'Bad score.' }, 400);
    const me = await DB.prepare('SELECT name FROM users WHERE id=?').bind(uid).first();
    if (!me) return J({ error: 'Not signed in.' }, 401);
    const old = (await DB.prepare('SELECT score FROM lb WHERE g=? AND uid=?').bind(g, uid).first())?.score || 0;
    if (sc <= old) return J({ passed: 0 });
    const pr = (await DB.prepare('SELECT uid FROM lb WHERE g=? AND uid!=? AND score>=? AND score<? ORDER BY score DESC LIMIT 10').bind(g, uid, old, sc).all()).results;
    await DB.batch([
      DB.prepare('INSERT OR REPLACE INTO lb VALUES(?,?,?,?,?)').bind(g, uid, me.name, sc, now),
      ...pr.map(r => DB.prepare('INSERT INTO notif(uid,txt,t) VALUES(?,?,?)').bind(r.uid, `${me.name} passed your ${g} score with ${sc}!`, now))
    ]);
    return J({ passed: pr.length });
  }
  if (p === 'notifs') {
    const r = (await DB.prepare('SELECT id,txt FROM notif WHERE uid=? ORDER BY id LIMIT 20').bind(uid).all()).results;
    if (r.length) await DB.batch(r.map(x => DB.prepare('DELETE FROM notif WHERE id=?').bind(x.id)));
    return J(r);
  }
  return J({ error: 'Not found.' }, 404);
}

export default {
  async fetch(req, env) {
    const u = new URL(req.url);
    if (!u.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    try { return await api(req, env, u.pathname.slice(5), u); }
    catch (e) { return J({ error: 'Server error: ' + e.message }, 500); }
  }
};
