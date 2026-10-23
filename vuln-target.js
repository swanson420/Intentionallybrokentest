#!/usr/bin/env node
/**
 * MERCYZERO FAIL TARGET: deliberately vulnerable. LOCAL TESTING ONLY.
 *
 * Run:   node vuln-target.js            (Node 18+, zero dependencies)
 * Env:   PORT=4000  CB_PORT=4001  HOST=127.0.0.1  FIXED=0|1
 *
 * Toggle vulnerable <-> fixed at runtime (to exercise FIXED / REGRESSED):
 *   curl 'localhost:4000/__control/fixed?on=1'    # all checks now pass
 *   curl 'localhost:4000/__control/fixed?on=0'    # back to vulnerable
 *   curl 'localhost:4000/__control/reset'         # clear revocations/uploads/callbacks
 *
 * Tokens (Authorization: Bearer <token>):
 *   alice-token (user, id 1) | bob-token (user, id 2) | admin-token (admin, id 99)
 *
 * Do NOT expose publicly. Default bind is loopback. All state is in memory.
 */
const http = require('http');
const crypto = require('crypto');

const PORT = +process.env.PORT || 4000;
const CB_PORT = +process.env.CB_PORT || 4001;
const HOST = process.env.HOST || (process.env.RENDER || process.env.RAILWAY_ENVIRONMENT || process.env.FLY_APP_NAME || process.env.KOYEB_APP_NAME ? '0.0.0.0' : '127.0.0.1');
let fixed = process.env.FIXED === '1';

// ---------- state ----------
const USERS = {
  'alice-token': { id: 1, name: 'alice', role: 'user' },
  'bob-token': { id: 2, name: 'bob', role: 'user' },
  'admin-token': { id: 99, name: 'admin', role: 'admin' },
};
const ORDERS = {
  1: { id: 1, ownerId: 1, item: 'widget', card: '4111-xxxx-1111' },
  2: { id: 2, ownerId: 2, item: 'gadget', card: '5500-xxxx-2222' },
};
const PROFILES = { 1: { name: 'alice', email: 'a@x.test', role: 'user' }, 2: { name: 'bob', email: 'b@x.test', role: 'user' } };
const SQL_ROWS = { 1: { id: 1, name: 'alice' }, 2: { id: 2, name: 'bob' } };
let revoked = new Set();
let uploads = {};
let callbacks = [];
let hits = {};
const ALLOWED_ORIGINS = ['https://app.example.test'];
const SECRET = crypto.randomBytes(16).toString('hex');

// ---------- helpers ----------
const b64u = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function send(res, status, body, headers = {}) {
  const isObj = body !== null && typeof body === 'object' && !Buffer.isBuffer(body);
  res.writeHead(status, { 'Content-Type': isObj ? 'application/json' : 'text/plain', ...headers });
  res.end(isObj ? JSON.stringify(body) : body);
}
const html = (res, status, body, h = {}) => send(res, status, body, { 'Content-Type': 'text/html', ...h });

function readBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on('data', (c) => { n += c.length; if (n > limit) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
const parseJson = (buf) => { try { return JSON.parse(buf.toString() || '{}'); } catch { return {}; } };

function authUser(req) {
  // Accept Authorization: Bearer <token>, or x-access-key: <token> (with or without 'Bearer ').
  const raw = req.headers.authorization || req.headers['x-access-key'] || '';
  const m = /^(?:Bearer\s+)?(\S+)$/i.exec(String(raw).trim());
  return m ? { token: m[1], user: USERS[m[1]] } : { token: null, user: null };
}

// ---------- per-request security headers (only when fixed) ----------
function hardening(res) {
  if (!fixed) return;
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}

// ---------- route handlers ----------
const routes = [];
const route = (method, path, fn) => routes.push({ method, path, fn });

route('GET', '/', (req, res) => html(res, 200, `<h1>MERCYZERO fail target</h1><p>mode: <b>${fixed ? 'FIXED' : 'VULNERABLE'}</b></p>
<pre>${esc(routes.map((r) => r.method + ' ' + r.path).join('\n'))}</pre>`));

// --- same-origin SSRF callback receiver (works on Railway, which exposes one port) ---
for (const m of ['GET', 'POST']) route(m, '/__cb/*', (req, res) => {
  callbacks.push({ at: new Date().toISOString(), method: req.method, url: req.url, ua: req.headers['user-agent'] });
  send(res, 200, 'callback received');
});

// --- control plane ---
route('GET', '/__control/fixed', (req, res, u) => { fixed = u.searchParams.get('on') === '1'; send(res, 200, { fixed }); });
route('GET', '/__control/status', (req, res) => send(res, 200, { fixed, hits }));
route('GET', '/__control/reset', (req, res) => { revoked = new Set(); uploads = {}; callbacks = []; hits = {}; send(res, 200, { ok: true }); });
route('GET', '/__callbacks', (req, res) => send(res, 200, callbacks));

// --- CORS ---
route('GET', '/fail/cors/profile', (req, res) => {
  const origin = req.headers.origin;
  if (origin) {
    if (!fixed) { res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Access-Control-Allow-Credentials', 'true'); }
    else if (ALLOWED_ORIGINS.includes(origin)) { res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Access-Control-Allow-Credentials', 'true'); res.setHeader('Vary', 'Origin'); }
  }
  send(res, 200, { user: 'alice', email: 'a@x.test', apiKey: 'sk_test_SECRET' });
});

// --- open redirect ---
route('GET', '/fail/redirect', (req, res, u) => {
  const next = u.searchParams.get('next') || u.searchParams.get('url') || '/';
  if (fixed && !(next.startsWith('/') && !next.startsWith('//'))) return send(res, 400, { error: 'invalid redirect' });
  res.writeHead(302, { Location: next }); res.end();
});

// --- session cookie ---
route('GET', '/fail/cookie', (req, res) => {
  const sid = crypto.randomBytes(8).toString('hex');
  const flags = fixed ? '; Path=/; Secure; HttpOnly; SameSite=Strict' : '';
  send(res, 200, { ok: true }, { 'Set-Cookie': `sid=${sid}${flags}` });
});

// --- JWT ---
route('GET', '/fail/jwt', (req, res) => {
  if (!fixed) {
    const tok = `${b64u({ alg: 'none', typ: 'JWT' })}.${b64u({ sub: '1', role: 'user' })}.`; // alg none, no exp
    return send(res, 200, { token: tok }, { 'Set-Cookie': `jwt=${tok}` });
  }
  const h = b64u({ alg: 'HS256', typ: 'JWT' });
  const p = b64u({ sub: '1', role: 'user', exp: Math.floor(Date.now() / 1000) + 900 });
  const sig = crypto.createHmac('sha256', SECRET).update(`${h}.${p}`).digest('base64url');
  send(res, 200, { token: `${h}.${p}.${sig}` });
});

// --- rate limit ---
const bucket = [];
route('GET', '/fail/ratelimit', (req, res) => {
  if (fixed) {
    const now = Date.now();
    while (bucket.length && now - bucket[0] > 10_000) bucket.shift();
    if (bucket.length >= 10) return send(res, 429, { error: 'slow down' }, { 'Retry-After': '10' });
    bucket.push(now);
  }
  send(res, 200, { ok: true });
});

// --- reflected XSS ---
route('GET', '/fail/xss', (req, res, u) => {
  const q = u.searchParams.get('q') || '';
  html(res, 200, `<html><body><h2>Results for: ${fixed ? esc(q) : q}</h2></body></html>`);
});

// --- error-based SQLi (simulated, no real DB) ---
route('GET', '/fail/sqli', (req, res, u) => {
  const id = u.searchParams.get('id') || '1';
  if (fixed) return send(res, SQL_ROWS[id] ? 200 : 404, SQL_ROWS[id] || { error: 'not found' });
  const query = `SELECT * FROM users WHERE id = '${id}'`;
  if (/['"\\;]|--/.test(id)) {
    return send(res, 500, `SQLITE_ERROR: unrecognized token: "'" near "${id}"\nYou have an error in your SQL syntax; check the manual near '${id}' at line 1\nQuery: ${query}`);
  }
  send(res, SQL_ROWS[id] ? 200 : 404, SQL_ROWS[id] || { error: 'not found' });
});

// --- disclosure ---
const LEAKS = {
  '/.env': 'DB_PASSWORD=hunter2\nAWS_SECRET_ACCESS_KEY=AKIAFAKEFAKEFAKE\nJWT_SECRET=changeme\n',
  '/backup.sql': "-- MySQL dump\nINSERT INTO users VALUES (1,'alice','$2b$10$FAKEHASH');\n",
  '/.git/config': '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@github.com:acme/private.git\n',
};
for (const [p, body] of Object.entries(LEAKS)) route('GET', p, (req, res) => (fixed ? send(res, 404, 'not found') : send(res, 200, body)));

// --- GraphQL introspection ---
async function graphql(req, res, u) {
  let query = u.searchParams.get('query') || '';
  if (req.method === 'POST') query = parseJson(await readBody(req)).query || query;
  if (/__schema|__type/.test(query)) {
    if (fixed) return send(res, 200, { errors: [{ message: 'GraphQL introspection is disabled' }] });
    return send(res, 200, { data: { __schema: { queryType: { name: 'Query' }, types: [
      { name: 'Query', kind: 'OBJECT', fields: [{ name: 'hello' }, { name: 'users' }, { name: 'adminSecrets' }] },
      { name: 'User', kind: 'OBJECT', fields: [{ name: 'id' }, { name: 'email' }, { name: 'passwordHash' }] },
    ] } } });
  }
  send(res, 200, { data: { hello: 'world' } });
}
route('GET', '/graphql', graphql);
route('POST', '/graphql', graphql);

// --- logic / parameter tampering ---
route('GET', '/fail/logic/admin', (req, res, u) => {
  const role = u.searchParams.get('role');
  if (!fixed && role === 'admin') return send(res, 200, { secret: 'admin panel data' });
  send(res, 403, { error: 'forbidden' });
});
route('GET', '/fail/logic/checkout', (req, res, u) => {
  const qty = Math.max(1, +u.searchParams.get('qty') || 1);
  const price = fixed ? 19.99 : +u.searchParams.get('price') || 19.99; // client controls price
  send(res, 200, { item: 'widget', qty, price, total: +(price * qty).toFixed(2) });
});

// --- authorization (missing auth) ---
route('GET', '/fail/authz/secret', (req, res) => {
  if (fixed && !authUser(req).user) return send(res, 401, { error: 'unauthorized' });
  send(res, 200, { secret: 'internal-report-Q3' });
});

// --- IDOR ---
const idor = (req, res, u) => {
  const { user } = authUser(req);
  if (!user) return send(res, 401, { error: 'unauthorized' });
  const pathId = u.pathname.split('/').pop();
  const o = ORDERS[u.searchParams.get('id') || pathId];
  if (!o) return send(res, 404, { error: 'not found' });
  if (fixed && o.ownerId !== user.id && user.role !== 'admin') return send(res, 403, { error: 'forbidden' });
  send(res, 200, o);
};
route('GET', '/fail/idor/orders', idor);       // ?id=1
route('GET', '/fail/idor/orders/*', idor);     // /fail/idor/orders/1  (path style)

// --- BFLA ---
route('POST', '/fail/bfla/admin/delete-user', (req, res, u) => {
  const { user } = authUser(req);
  if (!user) return send(res, 401, { error: 'unauthorized' });
  if (fixed && user.role !== 'admin') return send(res, 403, { error: 'admin only' });
  send(res, 200, { deleted: u.searchParams.get('id') || '2', by: user.name });
});

// --- BOPLA / mass assignment ---
async function bopla(req, res) {
  const { user } = authUser(req);
  if (!user) return send(res, 401, { error: 'unauthorized' });
  const body = parseJson(await readBody(req));
  const prof = PROFILES[user.id] || (PROFILES[user.id] = { name: user.name, role: user.role });
  if (fixed) { for (const k of ['name', 'email']) if (k in body) prof[k] = body[k]; }
  else Object.assign(prof, body); // applies role, isAdmin, etc.
  send(res, 200, prof);
}
route('GET', '/fail/bopla/profile', (req, res) => {
  const { user } = authUser(req);
  if (!user) return send(res, 401, { error: 'unauthorized' });
  send(res, 200, PROFILES[user.id] || (PROFILES[user.id] = { name: user.name, role: user.role }));
});
route('POST', '/fail/bopla/profile', bopla);
route('PATCH', '/fail/bopla/profile', bopla);

// --- token revocation ---
route('POST', '/auth/revoke', (req, res) => {
  const { token, user } = authUser(req);
  if (!user) return send(res, 401, { error: 'unauthorized' });
  revoked.add(token); send(res, 200, { revoked: true });
});
route('GET', '/fail/revocation/me', (req, res) => {
  const { token, user } = authUser(req);
  if (!user) return send(res, 401, { error: 'unauthorized' });
  if (fixed && revoked.has(token)) return send(res, 401, { error: 'token revoked' });
  send(res, 200, { me: user.name });
});

// --- upload ---
route('POST', '/fail/upload', async (req, res, u) => {
  const buf = await readBody(req);
  const ct = req.headers['content-type'] || 'application/octet-stream';
  let name = (u.searchParams.get('name') || req.headers['x-filename'] || 'file.bin').replace(/[\\/]/g, '_');
  if (fixed) {
    if (!['image/png', 'image/jpeg'].includes(ct) || buf.length > 100_000) return send(res, 415, { error: 'unsupported file' });
    name = crypto.randomBytes(6).toString('hex') + (ct === 'image/png' ? '.png' : '.jpg');
  }
  uploads[name] = { buf, ct: fixed ? ct : ct };
  send(res, 201, { url: `/uploads/${name}`, contentType: ct, size: buf.length });
});
route('GET', '/uploads/*', (req, res, u) => {
  const f = uploads[decodeURIComponent(u.pathname.slice('/uploads/'.length))];
  if (!f) return send(res, 404, 'not found');
  res.writeHead(200, { 'Content-Type': f.ct, ...(fixed ? { 'X-Content-Type-Options': 'nosniff', 'Content-Disposition': 'attachment' } : {}) });
  res.end(f.buf);
});

// --- app hardening: leaks stack trace + 500 on hostile input ---
route('GET', '/fail/hardening', (req, res, u) => {
  const vals = [...u.searchParams.values()];
  if (vals.length === 0) return send(res, 200, { ok: true, hint: 'add a query parameter' });
  if (fixed) return send(res, 400, { error: 'invalid input' });
  const bad = vals.find((v) => /['"<>;%\\{}]|\.\.|\$|\x00/.test(v) || v.length > 200) || vals[0];
  const e = new Error(`Unhandled input: ${bad.slice(0, 80)}`);
  send(res, 500, `Internal Server Error\n${e.stack}\n    at /opt/render/project/src/vuln-target.js:handler\nDB_HOST=10.0.3.7 NODE_ENV=production`);
});

// --- SSRF ---
route('GET', '/fail/ssrf', async (req, res, u) => {
  const target = u.searchParams.get('url');
  if (!target) return send(res, 400, { error: 'url required' });
  if (fixed) return send(res, 400, { error: 'url not allowed' });
  let t; try { t = new URL(target); } catch { return send(res, 400, { error: 'bad url' }); }
  // Safety rail: only allow targets on this app itself (own public host or loopback).
  const own = (req.headers.host || '').split(':')[0];
  if (!['localhost', '127.0.0.1', own].includes(t.hostname)) return send(res, 400, { error: 'blocked by test-target safety rail (self-only SSRF)' });
  try {
    const r = await fetch(t, { signal: AbortSignal.timeout(3000) });
    send(res, 200, { status: r.status, body: (await r.text()).slice(0, 500) });
  } catch (e) { send(res, 502, { error: String(e.message) }); }
});

// ---------- dispatcher ----------
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  console.log(`${new Date().toISOString()} ${req.method} ${u.pathname}${u.search} origin=${req.headers.origin || '-'} auth=${req.headers.authorization ? 'yes' : 'no'}`);
  hits[u.pathname] = (hits[u.pathname] || 0) + 1;
  hardening(res);

  // --- SSRF via header: MERCYZERO sends x-mercyzero-callback-url; vulnerable mode fetches it ---
  const cbHdr = req.headers['x-mercyzero-callback-url'];
  if (!fixed && typeof cbHdr === 'string') {
    try {
      const t = new URL(cbHdr);
      const host = t.hostname;
      const privateNet = /^(169\.254\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) || host.endsWith('.internal') || host === 'metadata.google.internal';
      // Safety rail: only callback-shaped paths, never private/metadata ranges.
      if (/^https?:$/.test(t.protocol) && t.pathname.startsWith('/ssrf-callback/') && !privateNet) {
        fetch(t, { signal: AbortSignal.timeout(5000) }).catch(() => {});
      }
    } catch { /* ignore bad url */ }
  }

  if (req.method === 'OPTIONS') { // permissive preflight in vulnerable mode
    if (!fixed && req.headers.origin) {
      res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE');
      res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || '*');
    }
    res.writeHead(204); return res.end();
  }

  const r = routes.find((x) => x.method === req.method && (x.path === u.pathname || (x.path.endsWith('*') && u.pathname.startsWith(x.path.slice(0, -1)))));
  if (!r) return send(res, 404, { error: 'not found' });
  try { await r.fn(req, res, u); } catch (e) { if (!res.headersSent) send(res, 500, { error: String(e.message) }); }
});

// ---------- SSRF callback receiver ----------
const cb = http.createServer((req, res) => {
  const entry = { at: new Date().toISOString(), method: req.method, url: req.url, headers: req.headers };
  callbacks.push(entry);
  console.log(`[callback] ${req.method} ${req.url}`);
  res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('callback received');
});

server.listen(PORT, HOST, () => console.log(`fail target on http://${HOST}:${PORT}  mode=${fixed ? 'FIXED' : 'VULNERABLE'}`));
cb.listen(CB_PORT, HOST, () => console.log(`ssrf callback on http://${HOST}:${CB_PORT}  (hits visible at /__callbacks)`));
