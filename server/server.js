#!/usr/bin/env node
/*
 * ГБУК-ПРАКТИКА — сервер для размещения в сети театра.
 * Без сторонних зависимостей: только встроенные модули Node.js (версия 18 и новее).
 *
 *   node server/server.js init                      — первичная настройка: создать пользователей
 *   node server/server.js start                     — запуск (команда по умолчанию)
 *   node server/server.js reset-password <логин>    — выдать временный пароль (для администратора)
 *   node server/server.js list-users                — список пользователей
 *
 * Настройки задаются переменными окружения, см. server/ДЛЯ-АДМИНИСТРАТОРА.md.
 */
'use strict';
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const env = process.env;
const CFG = {
  port: Number(env.PORT) || 8080,
  host: env.HOST || '0.0.0.0',
  data: path.resolve(env.DATA_DIR || path.join(__dirname, 'data')),
  quota: Math.round((Number(env.QUOTA_GB) || 10) * 1024 ** 3),
  maxFile: Math.round((Number(env.MAX_FILE_MB) || 50) * 1024 ** 2),
  tlsCert: env.TLS_CERT || '',
  tlsKey: env.TLS_KEY || '',
  trustProxy: env.TRUST_PROXY === '1',
  csp: env.CSP !== 'off',
  idleMs: (Number(env.SESSION_IDLE_HOURS) || 12) * 3600e3,
  absMs: (Number(env.SESSION_MAX_DAYS) || 7) * 864e5,
  backupsKeep: Number(env.BACKUPS_KEEP) || 30,
};
const APP_HTML = path.resolve(__dirname, '..', 'index.html');
const BRIDGE_JS = path.join(__dirname, 'public', 'gbuk-server.js');
const SHARED_KEYS = ['gbuk_praktika_v9_events', 'gbuk_praktika_contract_registry_v1', 'gbuk_praktika_tax_settings_v1'];
const ROLES = { owner: 'Владелец', member: 'Сотрудник', accountant: 'Бухгалтер' };
const MAX_ACCOUNTANTS = 10;
const TRASH_DAYS = 30;

/* ---------------- storage helpers ---------------- */
const P = {
  users: () => path.join(CFG.data, 'users.json'),
  sessions: () => path.join(CFG.data, 'sessions.json'),
  state: () => path.join(CFG.data, 'state.json'),
  docsMeta: () => path.join(CFG.data, 'docs', 'meta.json'),
  docsDir: () => path.join(CFG.data, 'docs', 'files'),
  audit: () => path.join(CFG.data, 'audit.log'),
  backups: () => path.join(CFG.data, 'backups'),
};
function ensureDirs() {
  for (const d of [CFG.data, path.dirname(P.docsMeta()), P.docsDir(), P.backups()]) fs.mkdirSync(d, { recursive: true, mode: 0o700 });
}
function readJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
let writeChain = Promise.resolve();
function writeJSON(file, value) {
  const job = writeChain.then(async () => {
    const tmp = file + '.' + crypto.randomBytes(4).toString('hex') + '.tmp';
    await fsp.writeFile(tmp, JSON.stringify(value, null, 1), { mode: 0o600 });
    await fsp.rename(tmp, file);
  });
  writeChain = job.catch(() => {});
  return job;
}

/* ---------------- passwords ---------------- */
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
function hashPassword(pw, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(String(pw), salt, 64, SCRYPT).toString('hex') };
}
function checkPassword(pw, user) {
  const h = crypto.scryptSync(String(pw), user ? user.salt : 'x'.repeat(32), 64, SCRYPT);
  if (!user) return false;
  const ref = Buffer.from(user.hash, 'hex');
  return ref.length === h.length && crypto.timingSafeEqual(ref, h);
}
function tempPassword() {
  const abc = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const part = () => Array.from(crypto.randomBytes(4), b => abc[b % abc.length]).join('');
  return part() + '-' + part() + '-' + part();
}
function passwordProblem(pw, login) {
  pw = String(pw || '');
  if (pw.length < 10) return 'Пароль должен быть не короче 10 символов';
  if (pw.length > 200) return 'Слишком длинный пароль';
  if (!/[A-Za-zА-Яа-яЁё]/.test(pw) || !/\d/.test(pw)) return 'В пароле должны быть буквы и цифры';
  if (login && pw.toLowerCase().includes(String(login).toLowerCase())) return 'Пароль не должен содержать логин';
  return '';
}

/* ---------------- data ---------------- */
let users = [];
let sessions = {};
let state = { rev: 0, values: {}, updated: {} };
let docs = [];
function loadAll() {
  users = readJSON(P.users(), []);
  sessions = readJSON(P.sessions(), {});
  state = readJSON(P.state(), { rev: 0, values: {}, updated: {} });
  docs = readJSON(P.docsMeta(), []);
}
const saveUsers = () => writeJSON(P.users(), users);
const saveSessions = () => writeJSON(P.sessions(), sessions);
const saveState = () => writeJSON(P.state(), state);
const saveDocs = () => writeJSON(P.docsMeta(), docs);
const findUser = login => users.find(u => u.login === String(login || '').toLowerCase().trim());
const publicUser = u => ({ login: u.login, name: u.name, role: u.role, roleName: ROLES[u.role] || u.role, mustChange: !!u.mustChange });

function audit(req, user, action, details) {
  const line = JSON.stringify({ at: new Date().toISOString(), user: user ? user.login : null, ip: req ? clientIp(req) : 'cli', action, ...(details ? { details } : {}) });
  fs.appendFile(P.audit(), line + '\n', { mode: 0o600 }, () => {});
}

/* ---------------- sessions & rate limit ---------------- */
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
function clientIp(req) {
  if (CFG.trustProxy && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  return req.socket.remoteAddress || '';
}
function isHttps(req) {
  return !!req.socket.encrypted || (CFG.trustProxy && String(req.headers['x-forwarded-proto'] || '').startsWith('https'));
}
function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function sessionUser(req) {
  const tok = parseCookies(req).gbuk_sid;
  if (!tok || tok.length > 100) return null;
  const s = sessions[sha(tok)];
  if (!s) return null;
  const now = Date.now();
  if (now - s.lastSeen > CFG.idleMs || now - s.created > CFG.absMs) { delete sessions[sha(tok)]; saveSessions(); return null; }
  const u = findUser(s.login);
  if (!u || u.disabled) return null;
  if (now - s.lastSeen > 60e3) { s.lastSeen = now; saveSessions(); }
  return u;
}
function cookie(req, value, maxAge) {
  return `gbuk_sid=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}` + (isHttps(req) ? '; Secure' : '');
}
function dropSessions(login, exceptHash) {
  for (const [k, s] of Object.entries(sessions)) if (s.login === login && k !== exceptHash) delete sessions[k];
  saveSessions();
}
const fails = new Map();
function limited(key) {
  const f = fails.get(key);
  return f && f.until > Date.now();
}
function noteFail(key, max) {
  const now = Date.now();
  let f = fails.get(key);
  if (!f || now - f.first > 15 * 60e3) f = { n: 0, first: now, until: 0 };
  f.n++;
  if (f.n >= max) f.until = now + 15 * 60e3;
  fails.set(key, f);
}

/* ---------------- http helpers ---------------- */
function secHeaders(req, res, extraCsp) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=(self)');
  if (isHttps(req)) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  if (extraCsp === null) return;
  if (extraCsp) res.setHeader('Content-Security-Policy', extraCsp);
  else if (CFG.csp) res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' blob: https://cdnjs.cloudflare.com https://cdn.jsdelivr.net",
    "worker-src 'self' blob: https://cdnjs.cloudflare.com https://cdn.jsdelivr.net",
    "connect-src 'self' blob: data: https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://tessdata.projectnaptha.com",
    "img-src 'self' data: blob:", "style-src 'self' 'unsafe-inline'", "font-src 'self' data:", "media-src 'self' blob: data:",
    "object-src 'none'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'",
  ].join('; '));
}
function send(req, res, code, body, type = 'application/json; charset=utf-8', headers = {}) {
  secHeaders(req, res);
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', ...headers });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
const json = (req, res, code, obj, headers) => send(req, res, code, obj, 'application/json; charset=utf-8', headers);
const fail = (req, res, code, msg) => json(req, res, code, { error: msg });
function readBody(req, limit) {
  return new Promise((ok, no) => {
    const chunks = []; let n = 0;
    req.on('data', c => { n += c.length; if (n > limit) { no(Object.assign(new Error('too big'), { code: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => ok(Buffer.concat(chunks)));
    req.on('error', no);
  });
}
async function readJsonBody(req, limit = 6 * 1024 * 1024) {
  const buf = await readBody(req, limit);
  try { return JSON.parse(buf.toString('utf8') || '{}'); } catch { throw Object.assign(new Error('bad json'), { code: 400 }); }
}
function sameOrigin(req) {
  if (req.headers['x-gbuk'] !== '1') return false;
  const o = req.headers.origin;
  if (!o) return true;
  try { return new URL(o).host === req.headers.host; } catch { return false; }
}

/* ---------------- state merge ---------------- */
function mergeArrays(base, cur, val) {
  const k = o => (o && typeof o === 'object' && o.id != null ? String(o.id) : null);
  const bm = new Map(base.map(o => [k(o), o])), vm = new Map(val.map(o => [k(o), o]));
  const out = cur.slice(), idx = new Map(out.map((o, i) => [k(o), i]));
  for (const key of bm.keys()) if (key && !vm.has(key) && idx.has(key)) out[idx.get(key)] = undefined;
  for (const [key, o] of vm) {
    if (!key) continue;
    const b = bm.get(key);
    if (b && JSON.stringify(b) === JSON.stringify(o)) continue;
    if (idx.has(key) && out[idx.get(key)] !== undefined) out[idx.get(key)] = o;
    else out.push(o);
  }
  return out.filter(x => x !== undefined);
}
function mergeValue(base, cur, val) {
  if (cur === base || cur == null) return val;
  try {
    const b = base == null ? [] : JSON.parse(base), c = JSON.parse(cur), v = JSON.parse(val);
    if (Array.isArray(b) && Array.isArray(c) && Array.isArray(v)) return JSON.stringify(mergeArrays(b, c, v));
  } catch {}
  return val;
}

/* ---------------- documents ---------------- */
const DOC_ID = /^[A-Za-z0-9-]{8,64}$/;
const DOC_FIELDS = ['title', 'kind', 'party', 'number', 'docDate', 'note', 'fileName', 'createdAt', 'updatedAt', 'deletedAt', 'source', 'sourceId', 'syncedAt'];
const replacedIds = new Set();
const DOC_LOG_ACTIONS = ['docs.create', 'docs.replace', 'docs.save', 'docs.trash', 'docs.restore', 'docs.delete', 'trash.purge'];
async function readAudit(filter, limit) {
  let lines = [];
  try { lines = (await fsp.readFile(P.audit(), 'utf8')).trim().split('\n'); } catch { return []; }
  const out = [];
  for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) { let a; try { a = JSON.parse(lines[i]); } catch { continue; } if (!filter || filter(a)) out.push(a); }
  return out;
}
const usedBytes = () => docs.reduce((a, d) => a + (d.size || 0), 0);
const docFile = id => path.join(P.docsDir(), id);
function cleanMeta(m) {
  const out = {};
  for (const f of DOC_FIELDS) if (m[f] != null && m[f] !== '') out[f] = String(m[f]).slice(0, 600);
  return out;
}
function viewableType(d) {
  const e = (/\.([a-z0-9]+)$/i.exec(d.fileName || '') || [])[1] || '';
  const map = { pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', gif: 'image/gif', txt: 'text/plain; charset=utf-8', csv: 'text/plain; charset=utf-8', html: 'text/html; charset=utf-8', htm: 'text/html; charset=utf-8' };
  return map[e.toLowerCase()] || '';
}
async function purgeTrash() {
  const limit = Date.now() - TRASH_DAYS * 864e5, day = Date.now() - 864e5;
  const old = docs.filter(d => (d.deletedAt && new Date(d.deletedAt).getTime() < limit) || (d.pending && new Date(d.createdAt).getTime() < day));
  if (!old.length) return;
  for (const d of old) await fsp.rm(docFile(d.id), { force: true });
  docs = docs.filter(d => !old.includes(d));
  await saveDocs();
  audit(null, null, 'trash.purge', { count: old.length });
}
async function dailyBackup() {
  const day = new Date().toISOString().slice(0, 10), dir = path.join(P.backups(), day);
  await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
  for (const [src, name] of [[P.users(), 'users.json'], [P.state(), 'state.json'], [P.docsMeta(), 'docs-meta.json']]) {
    try { await fsp.copyFile(src, path.join(dir, name)); } catch {}
  }
  const all = (await fsp.readdir(P.backups())).filter(n => /^\d{4}-\d{2}-\d{2}$/.test(n)).sort();
  for (const n of all.slice(0, Math.max(0, all.length - CFG.backupsKeep))) await fsp.rm(path.join(P.backups(), n), { recursive: true, force: true });
}

/* ---------------- pages ---------------- */
const pageStyle = `:root{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;color:#343b39;background:#f6f5f0}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px}
.box{background:#fff;border:1px solid #e7e8e1;border-radius:16px;padding:28px;box-shadow:0 3px 15px #203b2810;width:100%;max-width:400px}
h1{font-size:22px;margin:0 0 4px}.sub{color:#737b76;margin:0 0 20px;font-size:14px}label{font-size:13px;font-weight:650;display:block;margin:14px 0 6px}
input{width:100%;padding:11px;border:1px solid #d6ded5;border-radius:9px;font:inherit}button{margin-top:20px;width:100%;background:#486b57;color:#fff;border:0;border-radius:9px;padding:12px;font:inherit;font-weight:650;cursor:pointer}
button:disabled{opacity:.6}.err{color:#a5403a;font-size:14px;margin-top:12px;min-height:1em}.hint{color:#747d76;font-size:12.5px;margin-top:14px;line-height:1.45}.brand{font-weight:750;font-size:15px;color:#385449;margin-bottom:16px}`;
function loginPage() {
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Вход — ГБУК-ПРАКТИКА</title><style>${pageStyle}</style></head><body>
<form class="box" id="f" autocomplete="on"><div class="brand">ГБУК-ПРАКТИКА · Театр «Практика»</div><h1>Вход</h1><p class="sub">Введите свой логин и пароль</p>
<label for="login">Логин</label><input id="login" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required maxlength="40">
<label for="password">Пароль</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="200">
<button type="submit" id="b">Войти</button><div class="err" id="e" role="alert"></div>
<p class="hint">Логин и первый пароль выдаёт администратор или владелец доступа. Забыли пароль — обратитесь к нему.</p></form>
<script>document.getElementById('f').onsubmit=async e=>{e.preventDefault();const b=document.getElementById('b'),er=document.getElementById('e');b.disabled=true;er.textContent='';
try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-GBUK':'1'},body:JSON.stringify({login:document.getElementById('login').value,password:document.getElementById('password').value})});
const j=await r.json().catch(()=>({}));if(r.ok){location.href=j.mustChange?'/change-password':'/';return}er.textContent=j.error||'Не удалось войти'}catch{er.textContent='Нет связи с сервером'}b.disabled=false};
document.getElementById('login').focus();</script></body></html>`;
}
function passwordPage(user) {
  const first = user.mustChange;
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Смена пароля — ГБУК-ПРАКТИКА</title><style>${pageStyle}</style></head><body>
<form class="box" id="f"><div class="brand">ГБУК-ПРАКТИКА · ${esc(user.name)}</div><h1>${first ? 'Придумайте свой пароль' : 'Смена пароля'}</h1>
<p class="sub">${first ? 'Вы вошли по временному паролю. Задайте личный пароль — его будете знать только вы.' : 'Новый пароль подействует сразу, на других устройствах нужно будет войти заново.'}</p>
<input type="text" name="username" autocomplete="username" value="${esc(user.login)}" hidden>
<label for="cur">${first ? 'Временный пароль' : 'Текущий пароль'}</label><input id="cur" type="password" autocomplete="current-password" required maxlength="200">
<label for="n1">Новый пароль</label><input id="n1" type="password" autocomplete="new-password" required maxlength="200">
<label for="n2">Повторите новый пароль</label><input id="n2" type="password" autocomplete="new-password" required maxlength="200">
<button type="submit" id="b">Сохранить пароль</button><div class="err" id="e" role="alert"></div>
<p class="hint">Не короче 10 символов, буквы и цифры. Удобно взять фразу, например «Премьера2026весной».${first ? '' : ' <a href="/">Вернуться в приложение</a>'}</p></form>
<script>document.getElementById('f').onsubmit=async e=>{e.preventDefault();const b=document.getElementById('b'),er=document.getElementById('e'),n1=document.getElementById('n1').value;
if(n1!==document.getElementById('n2').value){er.textContent='Новые пароли не совпадают';return}b.disabled=true;er.textContent='';
try{const r=await fetch('/api/password',{method:'POST',headers:{'Content-Type':'application/json','X-GBUK':'1'},body:JSON.stringify({current:document.getElementById('cur').value,next:n1})});
const j=await r.json().catch(()=>({}));if(r.ok){location.href='/';return}if(r.status===401){location.href='/login';return}er.textContent=j.error||'Не удалось сменить пароль'}catch{er.textContent='Нет связи с сервером'}b.disabled=false};</script></body></html>`;
}
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function appPage(user) {
  let html = fs.readFileSync(APP_HTML, 'utf8');
  const boot = { user: publicUser(user), people: Object.fromEntries(users.map(u => [u.login, u.name])), rev: state.rev, values: Object.fromEntries(SHARED_KEYS.map(k => [k, state.values[k] ?? null])) };
  const inject = `<script>window.__GBUK_BOOT__=${JSON.stringify(boot).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029')}</script><script src="/gbuk-server.js"></script>`;
  const i = html.indexOf('</head>');
  return i < 0 ? inject + html : html.slice(0, i) + inject + html.slice(i);
}

/* ---------------- routes ---------------- */
async function handle(req, res) {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname, m = req.method;
  const user = sessionUser(req);

  if (p === '/favicon.ico') { res.writeHead(204); return res.end(); }
  if (p === '/healthz') return send(req, res, 200, 'ok', 'text/plain; charset=utf-8');
  if (m === 'GET' && p === '/login') return user && !user.mustChange ? send(req, res, 302, '', 'text/plain', { Location: '/' }) : send(req, res, 200, loginPage(), 'text/html; charset=utf-8');
  if (m === 'GET' && p === '/change-password') return user ? send(req, res, 200, passwordPage(user), 'text/html; charset=utf-8') : send(req, res, 302, '', 'text/plain', { Location: '/login' });
  if (m === 'GET' && (p === '/' || p === '/index.html')) {
    if (!user) return send(req, res, 302, '', 'text/plain', { Location: '/login' });
    if (user.mustChange) return send(req, res, 302, '', 'text/plain', { Location: '/change-password' });
    return send(req, res, 200, appPage(user), 'text/html; charset=utf-8');
  }
  if (m === 'GET' && p === '/gbuk-server.js') {
    if (!user) return fail(req, res, 401, 'Нужно войти');
    return send(req, res, 200, fs.readFileSync(BRIDGE_JS), 'text/javascript; charset=utf-8');
  }
  if (!p.startsWith('/api/')) return send(req, res, 404, 'Не найдено', 'text/plain; charset=utf-8');

  const mutating = m !== 'GET' && m !== 'HEAD';
  if (mutating && !sameOrigin(req)) return fail(req, res, 403, 'Запрос отклонён');

  /* --- auth --- */
  if (p === '/api/login' && m === 'POST') {
    const b = await readJsonBody(req, 10_000);
    const login = String(b.login || '').toLowerCase().trim().slice(0, 40), ip = clientIp(req);
    if (limited('u:' + login) || limited('ip:' + ip)) { audit(req, null, 'login.locked', { login }); return fail(req, res, 429, 'Слишком много неудачных попыток. Попробуйте через 15 минут.'); }
    const u = findUser(login);
    const ok = checkPassword(String(b.password || ''), u);
    if (!ok || u.disabled) {
      noteFail('u:' + login, 5); noteFail('ip:' + ip, 30);
      audit(req, null, 'login.fail', { login });
      return fail(req, res, 401, u && u.disabled && ok ? 'Доступ заблокирован. Обратитесь к владельцу доступа.' : 'Неверный логин или пароль');
    }
    fails.delete('u:' + login);
    const tok = crypto.randomBytes(32).toString('base64url');
    sessions[sha(tok)] = { login: u.login, created: Date.now(), lastSeen: Date.now(), ip };
    u.lastLoginAt = new Date().toISOString();
    await Promise.all([saveSessions(), saveUsers()]);
    audit(req, u, 'login.ok');
    return json(req, res, 200, { ok: true, mustChange: !!u.mustChange }, { 'Set-Cookie': cookie(req, tok, Math.round(CFG.absMs / 1000)) });
  }
  if (p === '/api/logout' && m === 'POST') {
    const tok = parseCookies(req).gbuk_sid;
    if (tok) { delete sessions[sha(tok)]; await saveSessions(); }
    if (user) audit(req, user, 'logout');
    return json(req, res, 200, { ok: true }, { 'Set-Cookie': cookie(req, '', 0) });
  }
  if (!user) return fail(req, res, 401, 'Нужно войти');
  if (p === '/api/me' && m === 'GET') return json(req, res, 200, publicUser(user));
  if (p === '/api/password' && m === 'POST') {
    const b = await readJsonBody(req, 10_000);
    if (limited('pw:' + user.login)) return fail(req, res, 429, 'Слишком много попыток. Попробуйте через 15 минут.');
    if (!checkPassword(String(b.current || ''), user)) { noteFail('pw:' + user.login, 5); audit(req, user, 'password.fail'); return fail(req, res, 400, 'Текущий пароль указан неверно'); }
    const problem = passwordProblem(b.next, user.login);
    if (problem) return fail(req, res, 400, problem);
    if (checkPassword(String(b.next), user)) return fail(req, res, 400, 'Новый пароль должен отличаться от текущего');
    Object.assign(user, hashPassword(b.next), { mustChange: false, passwordChangedAt: new Date().toISOString() });
    await saveUsers();
    dropSessions(user.login, sha(parseCookies(req).gbuk_sid || ''));
    audit(req, user, 'password.change');
    return json(req, res, 200, { ok: true });
  }
  if (user.mustChange) return fail(req, res, 403, 'Сначала смените временный пароль');

  /* --- shared state --- */
  if (p === '/api/state' && m === 'GET') {
    const since = Number(url.searchParams.get('since'));
    if (Number.isFinite(since) && since === state.rev) return json(req, res, 200, { rev: state.rev });
    return json(req, res, 200, { rev: state.rev, values: Object.fromEntries(SHARED_KEYS.map(k => [k, state.values[k] ?? null])), updated: state.updated });
  }
  if (p === '/api/state' && m === 'POST') {
    const b = await readJsonBody(req);
    if (!SHARED_KEYS.includes(b.key)) return fail(req, res, 400, 'Неизвестный раздел данных');
    if (typeof b.value !== 'string') return fail(req, res, 400, 'Нет данных');
    try { JSON.parse(b.value); } catch { return fail(req, res, 400, 'Повреждённые данные'); }
    const cur = state.values[b.key] ?? null;
    const merged = mergeValue(b.base ?? null, cur, b.value);
    if (merged !== cur) {
      state.values[b.key] = merged;
      state.rev++;
      state.updated[b.key] = { by: user.login, at: new Date().toISOString() };
      await saveState();
      let count; try { const v = JSON.parse(merged); if (Array.isArray(v)) count = v.length; } catch {}
      audit(req, user, 'data.save', { key: b.key, count });
    }
    return json(req, res, 200, { rev: state.rev, value: merged });
  }

  /* --- documents --- */
  if (p === '/api/docs' && m === 'GET') return json(req, res, 200, docs.map(d => ({ ...d })));
  if (p === '/api/docs/log' && m === 'GET') {
    const limit = Math.min(500, Number(url.searchParams.get('limit')) || 100), names = Object.fromEntries(users.map(u => [u.login, u.name]));
    const list = await readAudit(a => DOC_LOG_ACTIONS.includes(a.action), limit);
    return json(req, res, 200, list.map(a => ({ at: a.at, user: a.user, name: a.user ? names[a.user] || a.user : 'Система', action: a.action, ...(a.details || {}) })));
  }
  if (p === '/api/docs/usage' && m === 'GET') return json(req, res, 200, { used: usedBytes(), quota: CFG.quota, count: docs.filter(d => !d.deletedAt).length });
  const dm = /^\/api\/docs\/([^/]+)(\/file)?$/.exec(p);
  if (dm) {
    const id = decodeURIComponent(dm[1]);
    if (!DOC_ID.test(id)) return fail(req, res, 400, 'Неверный идентификатор');
    const d = docs.find(x => x.id === id);
    if (dm[2] && m === 'GET') {
      if (!d) return fail(req, res, 404, 'Документ не найден');
      const type = viewableType(d), inline = url.searchParams.get('inline') === '1' && type;
      const name = String(d.fileName || 'document').replace(/[\r\n"]/g, '_');
      secHeaders(req, res, type.startsWith('text/html') ? "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:" : type === 'application/pdf' ? null : "sandbox; default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'");
      res.writeHead(200, { 'Content-Type': inline ? type : 'application/octet-stream', 'Cache-Control': 'private, no-store', 'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename="${encodeURIComponent(name).replace(/%20/g, ' ')}"; filename*=UTF-8''${encodeURIComponent(name)}` });
      return fs.createReadStream(docFile(id)).on('error', () => res.end()).pipe(res);
    }
    if (dm[2] && m === 'PUT') {
      const len = Number(req.headers['content-length'] || 0);
      if (len > CFG.maxFile) return fail(req, res, 413, `Файл больше ${Math.round(CFG.maxFile / 1048576)} МБ`);
      const prev = d ? d.size || 0 : 0;
      if (usedBytes() - prev + len > CFG.quota) { audit(req, user, 'docs.quota', { need: len }); return json(req, res, 413, { error: 'На сервере закончилось место для документов. Удалите ненужные документы из корзины или попросите администратора увеличить место.', name: 'QuotaExceededError' }); }
      let body;
      try { body = await readBody(req, CFG.maxFile); } catch (e) { return fail(req, res, e.code || 400, 'Файл слишком большой'); }
      const tmp = docFile(id) + '.upload';
      await fsp.writeFile(tmp, body, { mode: 0o600 });
      await fsp.rename(tmp, docFile(id));
      let name = ''; try { name = decodeURIComponent(String(req.headers['x-file-name'] || '')); } catch {}
      if (d) { d.size = body.length; if (name) d.fileName = name.slice(0, 250); d.updatedAt = new Date().toISOString(); d.uploadedBy = user.login; if (!d.pending) replacedIds.add(id); }
      else docs.push({ id, size: body.length, fileName: name.slice(0, 250) || 'document', createdAt: new Date().toISOString(), uploadedBy: user.login, pending: true });
      await saveDocs();
      audit(req, user, 'docs.file', { id, size: body.length });
      return json(req, res, 200, { ok: true, size: body.length });
    }
    if (!dm[2] && m === 'PUT') {
      const b = await readJsonBody(req, 100_000);
      if (!d) return fail(req, res, 400, 'Сначала загрузите файл');
      const wasDeleted = !!d.deletedAt, wasPending = !!d.pending, before = JSON.stringify(cleanMeta(d));
      const meta = cleanMeta(b);
      for (const f of DOC_FIELDS) if (f !== 'fileName') { if (f in meta) d[f] = meta[f]; else if (f === 'deletedAt' || f === 'note' || f === 'party' || f === 'number' || f === 'docDate') delete d[f]; }
      if (meta.fileName) d.fileName = meta.fileName;
      if (d.pending) { delete d.pending; d.createdBy = user.login; }
      d.updatedBy = user.login;
      await saveDocs();
      const action = wasPending ? 'docs.create' : replacedIds.delete(id) ? 'docs.replace' : d.deletedAt && !wasDeleted ? 'docs.trash' : !d.deletedAt && wasDeleted ? 'docs.restore' : 'docs.save';
      const changed = action !== 'docs.save' || before.replace(/"updatedAt":"[^"]*",?/, '') !== JSON.stringify(cleanMeta(d)).replace(/"updatedAt":"[^"]*",?/, '');
      if (changed) audit(req, user, action, { id, title: d.title, fileName: d.fileName, size: d.size, kind: d.kind });
      return json(req, res, 200, { ok: true });
    }
    if (!dm[2] && m === 'DELETE') {
      if (d) { docs = docs.filter(x => x !== d); await saveDocs(); await fsp.rm(docFile(id), { force: true }); audit(req, user, 'docs.delete', { id, title: d.title, fileName: d.fileName, size: d.size, kind: d.kind }); }
      return json(req, res, 200, { ok: true });
    }
  }

  /* --- access management (owner only) --- */
  if (p === '/api/users' || p.startsWith('/api/users/') || p === '/api/audit') {
    if (user.role !== 'owner') return fail(req, res, 403, 'Недостаточно прав');
    if (p === '/api/audit' && m === 'GET') {
      const limit = Math.min(500, Number(url.searchParams.get('limit')) || 100);
      return json(req, res, 200, await readAudit(null, limit));
    }
    if (p === '/api/users' && m === 'GET') return json(req, res, 200, users.map(u => ({ ...publicUser(u), disabled: !!u.disabled, lastLoginAt: u.lastLoginAt || null, createdAt: u.createdAt || null, createdBy: u.createdBy || null, manageable: u.role === 'accountant' })));
    if (p === '/api/users' && m === 'POST') {
      const b = await readJsonBody(req, 10_000);
      const login = String(b.login || '').toLowerCase().trim(), name = String(b.name || '').trim().slice(0, 80);
      if (!/^[a-z0-9._-]{3,32}$/.test(login)) return fail(req, res, 400, 'Логин: от 3 до 32 латинских букв, цифр, точек, дефисов');
      if (!name) return fail(req, res, 400, 'Укажите имя бухгалтера');
      if (findUser(login)) return fail(req, res, 400, 'Такой логин уже есть');
      if (users.filter(u => u.role === 'accountant').length >= MAX_ACCOUNTANTS) return fail(req, res, 400, 'Достигнуто максимальное число бухгалтеров');
      const pw = tempPassword();
      users.push({ login, name, role: 'accountant', ...hashPassword(pw), mustChange: true, createdAt: new Date().toISOString(), createdBy: user.login });
      await saveUsers();
      audit(req, user, 'user.create', { login, role: 'accountant' });
      return json(req, res, 200, { ok: true, login, tempPassword: pw });
    }
    const um = /^\/api\/users\/([^/]+)(?:\/(reset|disable|enable))?$/.exec(p);
    const target = um && findUser(decodeURIComponent(um[1]));
    if (!target) return fail(req, res, 404, 'Пользователь не найден');
    if (target.role !== 'accountant') return fail(req, res, 403, 'Можно управлять только доступами бухгалтеров');
    if (um[2] === 'reset' && m === 'POST') {
      const pw = tempPassword();
      Object.assign(target, hashPassword(pw), { mustChange: true });
      await saveUsers(); dropSessions(target.login);
      audit(req, user, 'user.reset', { login: target.login });
      return json(req, res, 200, { ok: true, tempPassword: pw });
    }
    if ((um[2] === 'disable' || um[2] === 'enable') && m === 'POST') {
      target.disabled = um[2] === 'disable';
      await saveUsers(); if (target.disabled) dropSessions(target.login);
      audit(req, user, 'user.' + um[2], { login: target.login });
      return json(req, res, 200, { ok: true });
    }
    if (!um[2] && m === 'DELETE') {
      users = users.filter(u => u !== target);
      await saveUsers(); dropSessions(target.login);
      audit(req, user, 'user.delete', { login: target.login });
      return json(req, res, 200, { ok: true });
    }
  }
  return fail(req, res, 404, 'Не найдено');
}

/* ---------------- cli ---------------- */
function cliInit() {
  ensureDirs(); loadAll();
  if (users.length) { console.log('Пользователи уже созданы. Для сброса пароля: node server/server.js reset-password <логин>'); process.exit(1); }
  const list = [['serzh', 'Серж', 'owner'], ['lyudmila', 'Людмила', 'member'], ['ekaterina', 'Екатерина', 'member']];
  const out = [];
  for (const [login, name, role] of list) {
    const pw = tempPassword();
    users.push({ login, name, role, ...hashPassword(pw), mustChange: true, createdAt: new Date().toISOString(), createdBy: 'admin' });
    out.push({ Имя: name, Логин: login, Роль: ROLES[role], 'Временный пароль': pw });
  }
  fs.writeFileSync(P.users(), JSON.stringify(users, null, 1), { mode: 0o600 });
  audit(null, null, 'init', { users: list.map(x => x[0]) });
  console.log('Созданы пользователи. Передайте каждому его логин и временный пароль лично — при первом входе пароль нужно будет сменить.');
  console.table(out);
}
function cliReset(login) {
  ensureDirs(); loadAll();
  const u = findUser(login);
  if (!u) { console.log('Пользователь не найден: ' + login); process.exit(1); }
  const pw = tempPassword();
  Object.assign(u, hashPassword(pw), { mustChange: true, disabled: false });
  for (const [k, s] of Object.entries(sessions)) if (s.login === u.login) delete sessions[k];
  fs.writeFileSync(P.users(), JSON.stringify(users, null, 1), { mode: 0o600 });
  fs.writeFileSync(P.sessions(), JSON.stringify(sessions, null, 1), { mode: 0o600 });
  audit(null, null, 'user.reset.cli', { login: u.login });
  console.log(`Временный пароль для ${u.name} (${u.login}): ${pw}\nПри входе его нужно будет сменить.`);
}
function cliList() {
  ensureDirs(); loadAll();
  console.table(users.map(u => ({ Имя: u.name, Логин: u.login, Роль: ROLES[u.role], Заблокирован: u.disabled ? 'да' : '', 'Последний вход': u.lastLoginAt || '' })));
}
function start() {
  ensureDirs(); loadAll();
  if (!users.length) { console.log('Пользователи не созданы. Сначала выполните: node server/server.js init'); process.exit(1); }
  if (!fs.existsSync(APP_HTML)) { console.log('Не найден файл приложения: ' + APP_HTML); process.exit(1); }
  const handler = (req, res) => handle(req, res).catch(err => {
    if (!res.headersSent) fail(req, res, err.code === 413 ? 413 : err.code === 400 ? 400 : 500, err.code === 413 ? 'Слишком большой запрос' : err.code === 400 ? 'Неверный запрос' : 'Ошибка сервера');
    if (!err.code) console.error(new Date().toISOString(), err);
  });
  const srv = CFG.tlsCert && CFG.tlsKey
    ? https.createServer({ cert: fs.readFileSync(CFG.tlsCert), key: fs.readFileSync(CFG.tlsKey) }, handler)
    : http.createServer(handler);
  srv.requestTimeout = 10 * 60e3;
  srv.listen(CFG.port, CFG.host, () => console.log(`ГБУК-ПРАКТИКА: ${CFG.tlsCert ? 'https' : 'http'}://${CFG.host}:${CFG.port} · данные: ${CFG.data} · место под документы: ${(CFG.quota / 1024 ** 3).toFixed(1)} ГБ`));
  const daily = () => { dailyBackup().catch(e => console.error('backup', e)); purgeTrash().catch(e => console.error('purge', e)); };
  daily(); setInterval(daily, 24 * 3600e3).unref();
  setInterval(() => { const now = Date.now(); let ch = false; for (const [k, s] of Object.entries(sessions)) if (now - s.lastSeen > CFG.idleMs || now - s.created > CFG.absMs) { delete sessions[k]; ch = true; } if (ch) saveSessions(); }, 3600e3).unref();
}

const [cmd, arg] = process.argv.slice(2);
if (cmd === 'init') cliInit();
else if (cmd === 'reset-password') cliReset(arg);
else if (cmd === 'list-users') cliList();
else if (!cmd || cmd === 'start') start();
else { console.log('Команды: init | start | reset-password <логин> | list-users'); process.exit(1); }

module.exports = { mergeArrays, mergeValue, passwordProblem };
