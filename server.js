/* =====================================================================
   Digital Legacy Manager — backend server
   Node.js (18+). No external dependencies: uses only the standard library.

   Security properties implemented server-side:
     - Passwords stored as scrypt hashes with per-user random salt
     - Sessions are HMAC-SHA256 signed tokens in httpOnly cookies
     - Asset contents encrypted at rest with AES-256-GCM
     - Decryption is authorisation-gated: a beneficiary can only obtain
       plaintext after the release workflow has completed
     - Every role check is enforced here, not in the browser
   ===================================================================== */

'use strict';

const http    = require('node:http');
const crypto  = require('node:crypto');
const fs      = require('node:fs');
const path    = require('node:path');
const url     = require('node:url');

const PORT     = process.env.PORT || 3000;
const ROOT     = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const PUBLIC   = path.join(ROOT, 'public');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------------------------------------------------------------------
   Secrets — generated once, then reused across restarts.
   In production these would come from a secrets manager, not a file.
   --------------------------------------------------------------------- */
const SECRET_FILE = path.join(DATA_DIR, 'secrets.json');
let SECRETS;
if (fs.existsSync(SECRET_FILE)) {
  SECRETS = JSON.parse(fs.readFileSync(SECRET_FILE, 'utf8'));
} else {
  SECRETS = {
    sessionKey: crypto.randomBytes(32).toString('hex'),
    masterKey:  crypto.randomBytes(32).toString('hex')
  };
  fs.writeFileSync(SECRET_FILE, JSON.stringify(SECRETS, null, 2));
}
const SESSION_KEY = Buffer.from(SECRETS.sessionKey, 'hex');
const MASTER_KEY  = Buffer.from(SECRETS.masterKey,  'hex');

/* =====================================================================
   STORAGE LAYER
   Uses node:sqlite when the runtime provides it (Node 22.5+), otherwise
   falls back to a JSON file. Both expose the same tiny interface, so the
   rest of the server does not care which is active.
   ===================================================================== */
let store, BACKEND;

function makeSqliteStore() {
  const { DatabaseSync } = require('node:sqlite');
  const db = new DatabaseSync(path.join(DATA_DIR, 'dlm.db'));
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, name TEXT, email TEXT UNIQUE, salt TEXT, hash TEXT,
      role TEXT, status TEXT, createdAt TEXT);
    CREATE TABLE IF NOT EXISTS assets (
      id TEXT PRIMARY KEY, ownerId TEXT, name TEXT, type TEXT, note TEXT,
      iv TEXT, tag TEXT, cipher TEXT, createdAt TEXT);
    CREATE TABLE IF NOT EXISTS wills (
      id TEXT PRIMARY KEY, ownerId TEXT UNIQUE, status TEXT, condition TEXT, updatedAt TEXT);
    CREATE TABLE IF NOT EXISTS allocations (
      id TEXT PRIMARY KEY, willId TEXT, assetId TEXT, beneficiaryId TEXT);
    CREATE TABLE IF NOT EXISTS requests (
      id TEXT PRIMARY KEY, ownerId TEXT, beneficiaryId TEXT, status TEXT,
      certRef TEXT, certBy TEXT, certNote TEXT,
      legalRef TEXT, execBy TEXT, execNote TEXT,
      createdAt TEXT, releasedAt TEXT);
    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY, userId TEXT, text TEXT, at TEXT, readFlag INTEGER);
    CREATE TABLE IF NOT EXISTS audit (
      id TEXT PRIMARY KEY, at TEXT, actor TEXT, action TEXT, detail TEXT);
  `);
  const all = (t) => db.prepare(`SELECT * FROM ${t}`).all();
  return {
    kind: 'sqlite',
    all,
    insert(t, row) {
      const k = Object.keys(row);
      db.prepare(`INSERT INTO ${t} (${k.join(',')}) VALUES (${k.map(() => '?').join(',')})`)
        .run(...k.map(x => row[x] === undefined ? null : row[x]));
    },
    update(t, id, patch) {
      const k = Object.keys(patch);
      if (!k.length) return;
      db.prepare(`UPDATE ${t} SET ${k.map(x => x + '=?').join(',')} WHERE id=?`)
        .run(...k.map(x => patch[x] === undefined ? null : patch[x]), id);
    },
    remove(t, where) {
      const k = Object.keys(where);
      db.prepare(`DELETE FROM ${t} WHERE ${k.map(x => x + '=?').join(' AND ')}`)
        .run(...k.map(x => where[x]));
    },
    reset() {
      ['users','assets','wills','allocations','requests','notifications','audit']
        .forEach(t => db.exec(`DELETE FROM ${t}`));
    }
  };
}

function makeJsonStore() {
  const file = path.join(DATA_DIR, 'dlm.json');
  const empty = { users:[], assets:[], wills:[], allocations:[], requests:[], notifications:[], audit:[] };
  let d = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : structuredClone(empty);
  for (const k of Object.keys(empty)) if (!d[k]) d[k] = [];
  const flush = () => fs.writeFileSync(file, JSON.stringify(d, null, 2));
  return {
    kind: 'json',
    all: t => d[t].map(r => ({ ...r })),
    insert(t, row) { d[t].push({ ...row }); flush(); },
    update(t, id, patch) {
      const r = d[t].find(x => x.id === id);
      if (r) { Object.assign(r, patch); flush(); }
    },
    remove(t, where) {
      d[t] = d[t].filter(r => !Object.keys(where).every(k => r[k] === where[k]));
      flush();
    },
    reset() { d = structuredClone(empty); flush(); }
  };
}

try { store = makeSqliteStore(); BACKEND = 'SQLite (node:sqlite)'; }
catch { store = makeJsonStore();  BACKEND = 'JSON file (node:sqlite unavailable on this Node version)'; }

/* =====================================================================
   CRYPTO
   ===================================================================== */
const uid = p => p + crypto.randomBytes(5).toString('hex');
const now = () => new Date().toISOString();

function hashPassword(pw, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(pw, salt, hash) {
  const cand = Buffer.from(crypto.scryptSync(pw, salt, 64).toString('hex'), 'hex');
  const real = Buffer.from(hash, 'hex');
  return cand.length === real.length && crypto.timingSafeEqual(cand, real);
}

/* AES-256-GCM. Per-owner key derived from the master key, so compromising
   one owner's derived key does not expose another owner's assets. */
function ownerKey(ownerId) {
  return crypto.hkdfSync('sha256', MASTER_KEY, Buffer.from(ownerId), Buffer.from('dlm-asset'), 32);
}
function encrypt(plain, ownerId) {
  const iv = crypto.randomBytes(12);
  const c  = crypto.createCipheriv('aes-256-gcm', Buffer.from(ownerKey(ownerId)), iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return { iv: iv.toString('hex'), tag: c.getAuthTag().toString('hex'), cipher: ct.toString('hex') };
}
function decrypt(rec, ownerId) {
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', Buffer.from(ownerKey(ownerId)), Buffer.from(rec.iv, 'hex'));
    d.setAuthTag(Buffer.from(rec.tag, 'hex'));
    return Buffer.concat([d.update(Buffer.from(rec.cipher, 'hex')), d.final()]).toString('utf8');
  } catch { return null; }
}

/* Signed session token: base64(payload).hmac */
function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig  = crypto.createHmac('sha256', SESSION_KEY).update(body).digest('base64url');
  return body + '.' + sig;
}
function readToken(tok) {
  if (!tok || !tok.includes('.')) return null;
  const [body, sig] = tok.split('.');
  const want = crypto.createHmac('sha256', SESSION_KEY).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(want);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}

/* =====================================================================
   DATA HELPERS
   ===================================================================== */
const T = {
  users:  () => store.all('users'),
  assets: () => store.all('assets'),
  wills:  () => store.all('wills'),
  allocs: () => store.all('allocations'),
  reqs:   () => store.all('requests'),
  notes:  () => store.all('notifications'),
  audit:  () => store.all('audit')
};
const userById  = id => T.users().find(u => u.id === id);
const userByMail= e  => T.users().find(u => u.email.toLowerCase() === String(e).toLowerCase());
const willOf    = o  => T.wills().find(w => w.ownerId === o);

function audit(actor, action, detail) {
  store.insert('audit', { id: uid('g'), at: now(), actor, action, detail });
}
function notify(userId, text) {
  store.insert('notifications', { id: uid('n'), userId, text, at: now(), readFlag: 0 });
}
const pub = u => ({ id:u.id, name:u.name, email:u.email, role:u.role, status:u.status });

/* =====================================================================
   SEED
   ===================================================================== */
function seed() {
  store.reset();
  const mk = (id, name, email, role) => {
    const { salt, hash } = hashPassword('demo1234');
    store.insert('users', { id, name, email, salt, hash, role, status:'active', createdAt: now() });
  };
  mk('u1','Aarav Mehta','aarav@dlm.demo','owner');
  mk('u2','Priya Nair','priya@dlm.demo','beneficiary');
  mk('u3','Dr. S. Rao','rao@dlm.demo','verifier');
  mk('u4','Adv. N. Sharma','sharma@dlm.demo','executor');
  mk('u5','System Admin','admin@dlm.demo','admin');

  const asset = (id, name, type, note, body) => {
    const e = encrypt(body, 'u1');
    store.insert('assets', { id, ownerId:'u1', name, type, note, iv:e.iv, tag:e.tag, cipher:e.cipher, createdAt: now() });
  };
  asset('a1','Primary Email Account','Account','Recovery codes and backup address.',
    'provider: mail.example.com\nuser: aarav.mehta\nrecovery: 4821-9930-1174');
  asset('a2','Property Deed (Scan)','Document','Registered sale deed, 2019.',
    'DEED No. TN/2019/44821\nRegistered: 14 Mar 2019\nSub-Registrar: Coimbatore North');
  asset('a3','Family Photo Archive','Media','Cloud album, 2004-2024.',
    'album: family-archive-2004-2024\nitems: 8,412\nstorage: cloud-drive');

  store.insert('wills', { id:'w1', ownerId:'u1', status:'active',
    condition:'Release all assigned assets to beneficiaries after a verified death certificate is accepted by the Verification Authority and the Legal Executor approves the request.',
    updatedAt: now() });
  store.insert('allocations', { id: uid('al'), willId:'w1', assetId:'a1', beneficiaryId:'u2' });
  store.insert('allocations', { id: uid('al'), willId:'w1', assetId:'a2', beneficiaryId:'u2' });

  audit('system','SEED','Demo dataset initialised');
}
if (!T.users().length) seed();

/* =====================================================================
   HTTP PLUMBING
   ===================================================================== */
function send(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type':'application/json', 'Content-Length': Buffer.byteLength(b) });
  res.end(b);
}
function body(req) {
  return new Promise((resolve, reject) => {
    let d = ''; let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > 1e6) { reject(new Error('payload too large')); req.destroy(); return; }
      d += c;
    });
    req.on('end', () => { try { resolve(d ? JSON.parse(d) : {}); } catch { resolve({}); } });
    req.on('error', reject);
  });
}
function cookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function currentUser(req) {
  const t = readToken(cookies(req).dlm);
  if (!t) return null;
  const u = userById(t.uid);
  return (u && u.status === 'active') ? u : null;
}

const MIME = { '.html':'text/html; charset=utf-8', '.css':'text/css', '.js':'text/javascript',
               '.svg':'image/svg+xml', '.ico':'image/x-icon', '.json':'application/json' };

function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const file = path.resolve(PUBLIC, rel);
  if (!file.startsWith(PUBLIC)) { res.writeHead(403).end('Forbidden'); return; }   // traversal guard
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, {'Content-Type':'text/plain'}).end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(buf);
  });
}

/* =====================================================================
   ROUTES
   ===================================================================== */
const FLOW_NEXT = { SUBMITTED:'CERT_VERIFIED', CERT_VERIFIED:'EXECUTOR_APPROVED', EXECUTOR_APPROVED:'RELEASED' };

async function api(req, res, pathname, query) {
  const me = currentUser(req);
  const m  = req.method;
  const need = (...roles) => {
    if (!me) { send(res, 401, { error:'Not signed in' }); return false; }
    if (roles.length && !roles.includes(me.role)) { send(res, 403, { error:'Your role cannot perform this action' }); return false; }
    return true;
  };

  /* ---------- auth ---------- */
  if (pathname === '/api/auth/login' && m === 'POST') {
    const { email, password } = await body(req);
    const u = userByMail(email || '');
    if (!u || !verifyPassword(String(password || ''), u.salt, u.hash)) {
      audit(String(email || 'unknown'), 'LOGIN_FAILED', 'Invalid credentials');
      return send(res, 401, { error:'Incorrect email or password.' });
    }
    if (u.status !== 'active') return send(res, 403, { error:'This account is suspended. Contact the administrator.' });
    const tok = signToken({ uid: u.id, exp: Date.now() + 8 * 3600 * 1000 });
    res.setHeader('Set-Cookie', `dlm=${tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`);
    audit(u.name, 'LOGIN', 'Signed in as ' + u.role);
    return send(res, 200, { user: pub(u) });
  }
  if (pathname === '/api/auth/logout' && m === 'POST') {
    if (me) audit(me.name, 'LOGOUT', 'Signed out');
    res.setHeader('Set-Cookie', 'dlm=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    return send(res, 200, { ok:true });
  }
  if (pathname === '/api/me' && m === 'GET') {
    return send(res, 200, { user: me ? pub(me) : null, backend: BACKEND });
  }

  /* ---------- assets ---------- */
  if (pathname === '/api/assets' && m === 'GET') {
    if (!need()) return;
    const allocs = T.allocs();
    const list = T.assets()
      .filter(a => me.role === 'admin' ? true : a.ownerId === me.id)
      .map(a => {
        const al = allocs.find(x => x.assetId === a.id);
        return { id:a.id, ownerId:a.ownerId, name:a.name, type:a.type, note:a.note,
                 createdAt:a.createdAt, encrypted:true,
                 beneficiaryId: al ? al.beneficiaryId : null };
      });
    return send(res, 200, { assets:list });
  }
  if (pathname === '/api/assets' && m === 'POST') {
    if (!need('owner')) return;
    const { name, type, note, content } = await body(req);
    if (!String(name||'').trim())    return send(res, 400, { error:'Asset name is required' });
    if (!String(content||'').trim()) return send(res, 400, { error:'Stored details are required' });
    const e = encrypt(String(content), me.id);
    const id = uid('a');
    store.insert('assets', { id, ownerId:me.id, name:String(name).trim(), type:String(type||'Other'),
      note:String(note||''), iv:e.iv, tag:e.tag, cipher:e.cipher, createdAt: now() });
    audit(me.name, 'ASSET_CREATE', `Added asset "${name}" (encrypted AES-256-GCM)`);
    return send(res, 201, { id });
  }
  let mAsset = pathname.match(/^\/api\/assets\/([\w]+)$/);
  if (mAsset && m === 'DELETE') {
    if (!need('owner')) return;
    const a = T.assets().find(x => x.id === mAsset[1]);
    if (!a || a.ownerId !== me.id) return send(res, 404, { error:'Asset not found' });
    store.remove('assets', { id:a.id });
    store.remove('allocations', { assetId:a.id });
    audit(me.name, 'ASSET_DELETE', `Deleted asset "${a.name}"`);
    return send(res, 200, { ok:true });
  }

  /* Authorisation-gated decryption. This is the core security rule:
     plaintext leaves the server only for the owner, or for a beneficiary
     whose request has reached RELEASED. */
  let mContent = pathname.match(/^\/api\/assets\/([\w]+)\/content$/);
  if (mContent && m === 'GET') {
    if (!need()) return;
    const a = T.assets().find(x => x.id === mContent[1]);
    if (!a) return send(res, 404, { error:'Asset not found' });

    let allowed = false, why = '';
    if (a.ownerId === me.id) { allowed = true; why = 'owner'; }
    else if (me.role === 'beneficiary') {
      const al  = T.allocs().find(x => x.assetId === a.id && x.beneficiaryId === me.id);
      const rel = T.reqs().find(r => r.ownerId === a.ownerId && r.beneficiaryId === me.id && r.status === 'RELEASED');
      if (al && rel) { allowed = true; why = 'released'; }
    }
    if (!allowed) {
      audit(me.name, 'ACCESS_DENIED', `Attempted to read "${a.name}" without authorisation`);
      return send(res, 403, { error:'You are not authorised to read this asset. Assets are released only after the executor approves.' });
    }
    const plain = decrypt(a, a.ownerId);
    if (plain === null) return send(res, 500, { error:'Decryption failed — stored data may be corrupt' });
    audit(me.name, 'ASSET_DECRYPT', `Decrypted "${a.name}" (${why})`);
    return send(res, 200, { content: plain });
  }

  /* ---------- will ---------- */
  if (pathname === '/api/will' && m === 'GET') {
    if (!need('owner')) return;
    const w = willOf(me.id);
    return send(res, 200, { will: w ? { ...w, allocations: T.allocs().filter(a => a.willId === w.id) } : null });
  }
  if (pathname === '/api/will' && m === 'POST') {
    if (!need('owner')) return;
    if (willOf(me.id)) return send(res, 409, { error:'A will already exists' });
    const { condition } = await body(req);
    store.insert('wills', { id: uid('w'), ownerId:me.id, status:'active', condition:String(condition||''), updatedAt: now() });
    audit(me.name, 'WILL_CREATE', 'Digital will created');
    return send(res, 201, { ok:true });
  }
  if (pathname === '/api/will' && m === 'PATCH') {
    if (!need('owner')) return;
    const w = willOf(me.id);
    if (!w) return send(res, 404, { error:'No will' });
    const { condition, status } = await body(req);
    const patch = { updatedAt: now() };
    if (condition !== undefined) patch.condition = String(condition);
    if (status !== undefined)    patch.status = status === 'active' ? 'active' : 'draft';
    store.update('wills', w.id, patch);
    audit(me.name, 'WILL_UPDATE', 'Will updated');
    return send(res, 200, { ok:true });
  }
  if (pathname === '/api/will/allocate' && m === 'POST') {
    if (!need('owner')) return;
    const w = willOf(me.id);
    if (!w) return send(res, 400, { error:'Create a will first' });
    const { assetId, beneficiaryId } = await body(req);
    const a = T.assets().find(x => x.id === assetId && x.ownerId === me.id);
    if (!a) return send(res, 404, { error:'Asset not found' });
    store.remove('allocations', { assetId });
    if (beneficiaryId) {
      const b = userById(beneficiaryId);
      if (!b || b.role !== 'beneficiary') return send(res, 400, { error:'Invalid beneficiary' });
      store.insert('allocations', { id: uid('al'), willId:w.id, assetId, beneficiaryId });
    }
    store.update('wills', w.id, { updatedAt: now() });
    audit(me.name, 'WILL_ASSIGN', `"${a.name}" → ${beneficiaryId ? userById(beneficiaryId).name : 'unassigned'}`);
    return send(res, 200, { ok:true });
  }

  /* ---------- requests ---------- */
  if (pathname === '/api/requests' && m === 'GET') {
    if (!need()) return;
    let rs = T.reqs();
    if (me.role === 'owner')       rs = rs.filter(r => r.ownerId === me.id);
    if (me.role === 'beneficiary') rs = rs.filter(r => r.beneficiaryId === me.id);
    rs = rs.map(r => ({ ...r, ownerName: (userById(r.ownerId)||{}).name,
                              beneficiaryName: (userById(r.beneficiaryId)||{}).name }));
    rs.sort((a,b) => b.createdAt.localeCompare(a.createdAt));
    return send(res, 200, { requests: rs });
  }
  if (pathname === '/api/requests' && m === 'POST') {
    if (!need('beneficiary')) return;
    const { ownerId, certRef } = await body(req);
    if (!String(certRef||'').trim()) return send(res, 400, { error:'Certificate reference is required' });
    const o = userById(ownerId);
    if (!o || o.role !== 'owner') return send(res, 400, { error:'Unknown estate owner' });
    const open = T.reqs().find(r => r.beneficiaryId === me.id && r.ownerId === ownerId &&
      !['CERT_REJECTED','EXECUTOR_REJECTED','RELEASED'].includes(r.status));
    if (open) return send(res, 409, { error:'You already have an open request for this estate' });
    const id = uid('R').toUpperCase();
    store.insert('requests', { id, ownerId, beneficiaryId:me.id, status:'SUBMITTED',
      certRef:String(certRef).trim(), createdAt: now() });
    audit(me.name, 'REQUEST_CREATE', `Access requested for estate of ${o.name}`);
    T.users().filter(u => u.role === 'verifier').forEach(v => notify(v.id, `New access request ${id} awaiting certificate verification.`));
    notify(ownerId, `Beneficiary ${me.name} raised access request ${id}.`);
    return send(res, 201, { id });
  }

  let mReq = pathname.match(/^\/api\/requests\/([\w]+)\/(verify|approve|release)$/);
  if (mReq && m === 'POST') {
    const [, rid, action] = mReq;

    /* Authorisation is checked before the record is looked up, so that an
       unauthorised caller cannot learn which request IDs exist. */
    const ROLE_FOR = { verify:'verifier', approve:'executor', release:'executor' };
    if (!need(ROLE_FOR[action])) return;

    const r = T.reqs().find(x => x.id === rid);
    if (!r) return send(res, 404, { error:'Request not found' });
    const data = await body(req);

    if (action === 'verify') {
      if (r.status !== 'SUBMITTED') return send(res, 409, { error:'This request is not awaiting verification' });
      const ok = !!data.approve;
      store.update('requests', rid, { status: ok ? 'CERT_VERIFIED' : 'CERT_REJECTED',
        certBy: me.name, certNote: String(data.note||'') });
      audit(me.name, ok ? 'CERT_VERIFIED' : 'CERT_REJECTED', `Request ${rid} — ${data.note||'no note'}`);
      notify(r.beneficiaryId, ok ? `Certificate verified for request ${rid}. Awaiting executor.`
                                 : `Certificate rejected for request ${rid}.`);
      notify(r.ownerId, `Request ${rid} certificate ${ok ? 'verified' : 'rejected'}.`);
      if (ok) T.users().filter(u => u.role === 'executor').forEach(x => notify(x.id, `Request ${rid} is ready for your decision.`));
      return send(res, 200, { ok:true });
    }

    if (action === 'approve') {
      if (r.status !== 'CERT_VERIFIED') return send(res, 409, { error:'This request is not awaiting a legal decision' });
      const ok = !!data.approve;
      if (ok && !String(data.legalRef||'').trim())
        return send(res, 400, { error:'A legal document reference is required to approve' });
      store.update('requests', rid, { status: ok ? 'EXECUTOR_APPROVED' : 'EXECUTOR_REJECTED',
        legalRef:String(data.legalRef||''), execBy:me.name, execNote:String(data.note||'') });
      audit(me.name, ok ? 'EXEC_APPROVED' : 'EXEC_REJECTED', `Request ${rid} — ${data.note||'no note'}`);
      notify(r.beneficiaryId, ok ? `Request ${rid} approved by the executor.` : `Request ${rid} was rejected.`);
      notify(r.ownerId, `Request ${rid} ${ok ? 'approved' : 'rejected'} by executor.`);
      return send(res, 200, { ok:true });
    }

    if (action === 'release') {
      if (r.status !== 'EXECUTOR_APPROVED') return send(res, 409, { error:'This request has not been approved' });
      store.update('requests', rid, { status:'RELEASED', releasedAt: now() });
      const n = T.allocs().filter(a => a.beneficiaryId === r.beneficiaryId &&
        T.assets().some(x => x.id === a.assetId && x.ownerId === r.ownerId)).length;
      audit(me.name, 'ASSETS_RELEASED', `Request ${rid} — ${n} asset(s) released`);
      notify(r.beneficiaryId, `${n} asset(s) have been released to you. Open "Released Assets".`);
      notify(r.ownerId, `Assets released for request ${rid}.`);
      return send(res, 200, { released:n });
    }
  }

  /* Assets a beneficiary may now read */
  if (pathname === '/api/released' && m === 'GET') {
    if (!need('beneficiary')) return;
    const out = T.reqs().filter(r => r.beneficiaryId === me.id && r.status === 'RELEASED').map(r => ({
      requestId: r.id, releasedAt: r.releasedAt, ownerName: (userById(r.ownerId)||{}).name,
      assets: T.allocs().filter(a => a.beneficiaryId === me.id)
        .map(a => T.assets().find(x => x.id === a.assetId && x.ownerId === r.ownerId))
        .filter(Boolean)
        .map(a => ({ id:a.id, name:a.name, type:a.type, note:a.note }))
    }));
    return send(res, 200, { estates: out });
  }

  /* ---------- notifications ---------- */
  if (pathname === '/api/notifications' && m === 'GET') {
    if (!need()) return;
    const list = T.notes().filter(n => n.userId === me.id).sort((a,b) => b.at.localeCompare(a.at));
    return send(res, 200, { notifications: list });
  }
  if (pathname === '/api/notifications/read' && m === 'POST') {
    if (!need()) return;
    T.notes().filter(n => n.userId === me.id && !n.readFlag)
             .forEach(n => store.update('notifications', n.id, { readFlag:1 }));
    return send(res, 200, { ok:true });
  }

  /* ---------- directory ---------- */
  if (pathname === '/api/beneficiaries' && m === 'GET') {
    if (!need('owner')) return;
    return send(res, 200, { users: T.users().filter(u => u.role === 'beneficiary' && u.status === 'active').map(pub) });
  }
  if (pathname === '/api/owners' && m === 'GET') {
    if (!need('beneficiary')) return;
    return send(res, 200, { users: T.users().filter(u => u.role === 'owner' && u.status === 'active').map(pub) });
  }

  /* ---------- admin ---------- */
  if (pathname === '/api/users' && m === 'GET') {
    if (!need('admin')) return;
    return send(res, 200, { users: T.users().map(pub) });
  }
  if (pathname === '/api/users' && m === 'POST') {
    if (!need('admin')) return;
    const { name, email, password, role } = await body(req);
    if (!name || !email || !password) return send(res, 400, { error:'All fields are required' });
    if (!['owner','beneficiary','verifier','executor','admin'].includes(role)) return send(res, 400, { error:'Invalid role' });
    if (userByMail(email)) return send(res, 409, { error:'That email already exists' });
    const { salt, hash } = hashPassword(String(password));
    store.insert('users', { id: uid('u'), name:String(name), email:String(email).toLowerCase(),
      salt, hash, role, status:'active', createdAt: now() });
    audit(me.name, 'USER_CREATE', `Created account ${email} (${role})`);
    return send(res, 201, { ok:true });
  }
  let mUser = pathname.match(/^\/api\/users\/([\w]+)$/);
  if (mUser && m === 'PATCH') {
    if (!need('admin')) return;
    const u = userById(mUser[1]);
    if (!u) return send(res, 404, { error:'User not found' });
    if (u.id === me.id) return send(res, 400, { error:'You cannot change your own account status' });
    const st = u.status === 'active' ? 'suspended' : 'active';
    store.update('users', u.id, { status: st });
    audit(me.name, st === 'active' ? 'USER_RESTORE' : 'USER_SUSPEND', u.email);
    notify(u.id, `Your account was ${st === 'active' ? 'restored' : 'suspended'} by an administrator.`);
    return send(res, 200, { status: st });
  }
  if (pathname === '/api/audit' && m === 'GET') {
    if (!need('admin')) return;
    return send(res, 200, { audit: T.audit().sort((a,b) => b.at.localeCompare(a.at)).slice(0, 300) });
  }
  if (pathname === '/api/stats' && m === 'GET') {
    if (!need('admin')) return;
    const rs = T.reqs();
    return send(res, 200, { stats: {
      users: T.users().length, assets: T.assets().length, wills: T.wills().length,
      requests: rs.length,
      inProgress: rs.filter(r => ['SUBMITTED','CERT_VERIFIED','EXECUTOR_APPROVED'].includes(r.status)).length,
      released: rs.filter(r => r.status === 'RELEASED').length
    }});
  }
  if (pathname === '/api/admin/reset' && m === 'POST') {
    if (!need('admin')) return;
    seed();
    res.setHeader('Set-Cookie', 'dlm=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    return send(res, 200, { ok:true });
  }

  return send(res, 404, { error:'No such endpoint' });
}

/* =====================================================================
   SERVER
   ===================================================================== */
const server = http.createServer((req, res) => {
  const { pathname, query } = url.parse(req.url, true);
  if (pathname.startsWith('/api/')) {
    api(req, res, pathname, query).catch(err => {
      console.error('API error:', err);
      if (!res.headersSent) send(res, 500, { error:'Internal server error' });
    });
  } else {
    serveStatic(req, res, pathname);
  }
});

server.listen(PORT, () => {
  console.log('');
  console.log('  Digital Legacy Manager');
  console.log('  ----------------------------------------------');
  console.log('  Server   : http://localhost:' + PORT);
  console.log('  Storage  : ' + BACKEND);
  console.log('  Accounts : aarav@dlm.demo (owner)');
  console.log('             priya@dlm.demo (beneficiary)');
  console.log('             rao@dlm.demo (verifier)');
  console.log('             sharma@dlm.demo (executor)');
  console.log('             admin@dlm.demo (admin)');
  console.log('  Password : demo1234');
  console.log('  ----------------------------------------------');
  console.log('  Press Ctrl+C to stop.');
  console.log('');
});
