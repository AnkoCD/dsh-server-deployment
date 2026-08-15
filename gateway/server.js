'use strict';
const http = require('http');
const https = require('https');
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { execFileSync, spawn } = require('child_process');
const zlib = require('zlib');
const { verifyPassword, timingSafeStr } = require('./auth.js');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = parseInt(process.env.PORT || '3081', 10);
const USERS_FILE = process.env.USERS_FILE || '/opt/deepseek-harness/gateway/users.json';
const SECRET_FILE = process.env.SECRET_FILE || '/opt/deepseek-harness/gateway/secret';
const USERS_DIR = process.env.USERS_DIR || '/opt/deepseek-harness/users';
const SESSION_TTL = parseInt(process.env.SESSION_TTL || '43200', 10);
const COOKIE_SECURE = (process.env.COOKIE_SECURE || '1') !== '0';
const DEEPSEEK_BASE_URL = process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com';
const MAX_IP_ATTEMPTS = parseInt(process.env.MAX_IP_ATTEMPTS || '20', 10);
const MAX_USER_ATTEMPTS = parseInt(process.env.MAX_USER_ATTEMPTS || '5', 10);
const WINDOW_MS = parseInt(process.env.WINDOW_MS || '900000', 10);
const LOCK_MS = parseInt(process.env.LOCK_MS || '900000', 10);
const COOKIE_NAME = 'dsh_session';
const CSRF_COOKIE = 'dsh_csrf';
const UPLOAD_HELPER = process.env.UPLOAD_HELPER || '/opt/deepseek-harness/bin/dsh-file-put';
const FILE_STAT_HELPER = process.env.FILE_STAT_HELPER || '/opt/deepseek-harness/bin/dsh-file-stat';
const FILE_READ_HELPER = process.env.FILE_READ_HELPER || '/opt/deepseek-harness/bin/dsh-file-read';
const FILE_LIST_HELPER = process.env.FILE_LIST_HELPER || '/opt/deepseek-harness/bin/dsh-file-list';
const UPLOAD_MAX_MB = parseInt(process.env.UPLOAD_MAX_MB || '100', 10);

// ---------- history page trimming + JSON gzip tuning ----------
// Huge agent sessions accumulate tens of thousands of streaming chunk events
// per page: the DSH host pages by *messages* (user/message, assistant/message)
// while keeping every tool/chunk event of the page, and it never compresses.
// The web client asks for the last 50 messages, parses/renders every returned
// event and aborts its own fetch after 30s ("The user aborted a request."),
// so a multi-MB page over a slow link fails. The gateway therefore trims
// oversized history pages to the last few messages at message boundaries (the
// same boundary rule the host applies) and gzips JSON responses the host
// leaves raw. Trimming never drops data: the page tail is kept, hasMore is
// forced true, and the client's beforeSeq paging walks the skipped range.
const HISTORY_TRIM_MESSAGES = parseInt(process.env.HISTORY_TRIM_MESSAGES || '6', 10);
const HISTORY_TRIM_MIN_EVENTS = parseInt(process.env.HISTORY_TRIM_MIN_EVENTS || '2000', 10);
const GZIP_MIN_BYTES = parseInt(process.env.GZIP_MIN_BYTES || '256', 10);
const HISTORY_BUF_MAX = 64 * 1024 * 1024;

function loadSecret() {
  try {
    const s = fs.readFileSync(SECRET_FILE, 'utf8').trim();
    if (s.length >= 32) return s;
  } catch (e) {}
  const s = crypto.randomBytes(32).toString('hex');
  try {
    fs.mkdirSync(path.dirname(SECRET_FILE), { recursive: true, mode: 0o700 });
    fs.writeFileSync(SECRET_FILE, s + '\n', { mode: 0o600 });
  } catch (e) { console.error('cannot persist session secret:', e.message); }
  return s;
}
const SECRET = loadSecret();

function hmac(data) {
  return crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
}

// ---------- users store (small JSON, cached) ----------
let usersCache = { version: 1, users: {} };
let usersCacheAt = 0;
function loadUsers() {
  const now = Date.now();
  if (now - usersCacheAt < 2000) return usersCache;
  try {
    usersCache = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch (e) { usersCache = { version: 1, users: {} }; }
  usersCacheAt = now;
  return usersCache;
}
function getUser(name) {
  const u = loadUsers().users;
  return (u && u[name]) || null;
}

// Whether the user already configured an API key (flag lives in users.json,
// maintained by the gateway and by host-side userctl).
function hasKey(user) {
  const u = getUser(user);
  return !!(u && u.keyConfigured);
}

// Persist the flag and refresh the in-memory cache so the very next request
// sees it (no 2s staleness on the /setup -> / redirect).
function setUserKeyFlag(user, val) {
  let db;
  try { db = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (e) { db = { version: 1, users: {} }; }
  if (db.users && db.users[user]) db.users[user].keyConfigured = !!val;
  try { fs.writeFileSync(USERS_FILE, JSON.stringify(db, null, 2) + '\n', { mode: 0o640 }); } catch (e) { console.error('setUserKeyFlag write failed:', e.message); }
  usersCache = db;
  usersCacheAt = Date.now();
}

// Ask the user's own DSH instance to persist the key. The instance's credentials
// store is 0600 and owned by that user's OS account, so the gateway must not
// write it directly; this loopback RPC is the only write path.
function rpcCredentialsSet(port, key) {
  return new Promise((resolve) => {
    const rpcId = 'gw-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
    const body = JSON.stringify({ type: 'client-request', rpcId: rpcId, method: 'credentials.set', payload: { ref: 'DEEPSEEK_API_KEY', value: key } });
    const req = http.request({
      host: '127.0.0.1', port: port, method: 'POST', path: '/api/credentials.set',
      headers: { 'content-type': 'application/json', 'host': '127.0.0.1:' + port, 'content-length': Buffer.byteLength(body) },
    }, (res) => {
      let data = '';
      res.on('data', (c) => data += c);
      res.on('end', () => {
        try {
          const j = JSON.parse(data);
          if (j && j.result && j.result.ok) resolve({ ok: true });
          else resolve({ ok: false, detail: (j && j.result && j.result.error && j.result.error.message) || '后端返回错误' });
        } catch (e) { resolve({ ok: false, detail: '后端响应解析失败' }); }
      });
    });
    req.on('error', (e) => resolve({ ok: false, detail: '后端服务不可用: ' + e.message }));
    req.setTimeout(10000, () => { req.destroy(); resolve({ ok: false, detail: '写入超时' }); });
    req.write(body);
    req.end();
  });
}

// ---------- rate limiting ----------
const ipFails = new Map();
const userFails = new Map();
function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}
function lockedUntil(map, key) {
  const e = map.get(key);
  if (!e) return 0;
  if (e.lockedUntil && Date.now() < e.lockedUntil) return e.lockedUntil;
  return 0;
}
function registerFailure(map, key, max) {
  const now = Date.now();
  let e = map.get(key);
  if (!e || now - e.windowStart > WINDOW_MS) { e = { count: 0, windowStart: now, lockedUntil: 0 }; map.set(key, e); }
  e.count += 1;
  if (e.count >= max) e.lockedUntil = now + LOCK_MS;
}
function checkAttempts(req, username) {
  const ip = clientIp(req);
  const a = lockedUntil(ipFails, ip);
  const b = lockedUntil(userFails, username);
  if (a || b) return { allowed: false, retryAfter: Math.ceil((Math.max(a, b) - Date.now()) / 1000) };
  return { allowed: true, retryAfter: 0 };
}
function recordFailure(req, username) {
  registerFailure(ipFails, clientIp(req), MAX_IP_ATTEMPTS);
  registerFailure(userFails, username, MAX_USER_ATTEMPTS);
  if (ipFails.size > 10000 || userFails.size > 10000) {
    const now = Date.now();
    for (const m of [ipFails, userFails]) for (const [k, v] of m) if (now - v.windowStart > WINDOW_MS + LOCK_MS) m.delete(k);
  }
}
function recordSuccess(req, username) {
  ipFails.delete(clientIp(req));
  userFails.delete(username);
}

// ---------- session ----------
function makeToken(user) {
  const payload = { u: user, exp: Math.floor(Date.now() / 1000) + SESSION_TTL, n: crypto.randomBytes(8).toString('hex') };
  const b = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return b + '.' + hmac(b);
}
function verifyToken(tok) {
  if (!tok || typeof tok !== 'string') return null;
  const i = tok.lastIndexOf('.');
  if (i <= 0) return null;
  const b = tok.slice(0, i);
  const sig = tok.slice(i + 1);
  if (!timingSafeStr(hmac(b), sig)) return null;
  let p;
  try { p = JSON.parse(Buffer.from(b, 'base64url').toString('utf8')); } catch (e) { return null; }
  if (!p || typeof p.exp !== 'number' || Date.now() / 1000 > p.exp) return null;
  return p;
}
function parseCookies(req) {
  const h = req.headers.cookie;
  const out = {};
  if (!h) return out;
  for (const part of String(h).split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k) { try { out[k] = decodeURIComponent(v); } catch (e) { out[k] = v; } }
  }
  return out;
}
function getSession(req) {
  const c = parseCookies(req);
  const tok = c[COOKIE_NAME];
  if (!tok) return null;
  const p = verifyToken(tok);
  if (!p || !p.u) return null;
  if (!getUser(p.u)) return null;
  return p;
}
function cookieHeader(name, value, opts) {
  let s = name + '=' + value;
  if (opts.maxAge !== undefined) s += '; Max-Age=' + opts.maxAge;
  if (opts.path) s += '; Path=' + opts.path;
  s += '; HttpOnly';
  if (COOKIE_SECURE) s += '; Secure';
  s += '; SameSite=' + (opts.sameSite || 'Lax');
  return s;
}
function setSession(res, user) {
  res.setHeader('Set-Cookie', cookieHeader(COOKIE_NAME, makeToken(user), { maxAge: SESSION_TTL, path: '/' }));
}
function clearSession(res) {
  res.setHeader('Set-Cookie', cookieHeader(COOKIE_NAME, '', { maxAge: 0, path: '/' }));
}

// ---------- security headers (gateway-origin pages) ----------
function secHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'none'; connect-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'");
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
}

// ---------- body reader ----------
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
// Raw binary body reader (uploads); rejects past the limit.
function readBodyBuf(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function parseForm(body) {
  const out = {};
  for (const pair of body.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    const k = eq < 0 ? pair : pair.slice(0, eq);
    const v = eq < 0 ? '' : pair.slice(eq + 1);
    try { out[decodeURIComponent(k.replace(/\+/g, ' '))] = decodeURIComponent(v.replace(/\+/g, ' ')); }
    catch (e) {}
  }
  return out;
}

// ---------- key validation against DeepSeek ----------
function validateKey(key, timeoutMs) {
  return new Promise((resolve) => {
    let u;
    try { u = new url.URL(DEEPSEEK_BASE_URL); } catch (e) { return resolve({ ok: true, warning: '基础 URL 无效，已跳过校验' }); }
    const opts = {
      hostname: u.hostname,
      port: u.port || 443,
      path: '/models',
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + key, 'Accept': 'application/json' },
      timeout: timeoutMs,
    };
    const req = https.request(opts, (res) => {
      res.resume();
      res.on('end', () => {
        if (res.statusCode === 200) resolve({ ok: true });
        else if (res.statusCode === 401 || res.statusCode === 403) resolve({ ok: false, detail: 'DeepSeek 拒绝了该 Key（' + res.statusCode + '）' });
        else resolve({ ok: true, warning: '验证接口返回 ' + res.statusCode + '，已保存但请确认 Key 有效' });
      });
    });
    req.on('timeout', () => { req.destroy(); resolve({ ok: true, warning: '验证超时，已保存；请稍后在应用中确认' }); });
    req.on('error', () => resolve({ ok: true, warning: '无法连接验证接口，已保存；请稍后在应用中确认' }));
  });
}

// ---------- HTML pages ----------
function htmlShell(title, bodyHtml) {
  return [
    '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<title>', title, ' · DeepSeek Harness</title>',
    '<style>',
    ':root{--bg:#0b0f17;--panel:#111726;--panel2:#161d2e;--text:#e6e9f0;--muted:#8a93a6;--accent:#3b82f6;--err:#f87171;--ok:#34d399;--border:#232b3d}',
    '*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;background:radial-gradient(1200px 800px at 50% -10%,#16233b 0%,var(--bg) 55%);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}',
    '.card{width:100%;max-width:400px;background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:36px 32px;box-shadow:0 20px 60px rgba(0,0,0,.45)}',
    '.brand{display:flex;align-items:center;gap:12px;margin-bottom:6px}.logo{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,#2563eb,#7c3aed);display:flex;align-items:center;justify-content:center;font-weight:800;color:#fff;font-size:20px}',
    '.brand h1{font-size:20px;margin:0;font-weight:700}.brand .sub{font-size:12px;color:var(--muted)}',
    'p.lead{color:var(--muted);font-size:13.5px;margin:6px 0 22px;line-height:1.6}',
    'label{display:block;font-size:13px;color:var(--muted);margin:14px 0 6px}',
    'input{width:100%;background:var(--panel2);border:1px solid var(--border);border-radius:10px;color:var(--text);padding:12px 14px;font-size:15px;outline:none}input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.18)}',
    'button{margin-top:22px;width:100%;background:linear-gradient(135deg,#2563eb,#7c3aed);border:0;border-radius:10px;color:#fff;font-size:15px;font-weight:600;padding:12px;cursor:pointer}button:hover{filter:brightness(1.08)}button:disabled{opacity:.6;cursor:not-allowed}',
    '.msg{display:none;margin-top:16px;padding:11px 13px;border-radius:9px;font-size:13.5px;line-height:1.5}.msg.err{display:block;background:rgba(248,113,113,.12);color:var(--err);border:1px solid rgba(248,113,113,.25)}.msg.ok{display:block;background:rgba(52,211,153,.12);color:var(--ok);border:1px solid rgba(52,211,153,.25)}',
    '.hint{font-size:12.5px;color:var(--muted);margin-top:14px;line-height:1.6}',
    'code{background:var(--panel2);padding:2px 6px;border-radius:6px;font-size:12px}',
    '</style></head><body>',
    bodyHtml,
    '</body></html>',
  ].join('');
}

// Auth shell styled after the impeccable design reference: dark warm-black
// lacquer ground, kinpaku-gold accent, hairline gold rules, editorial type.
// Purposeful restraint: no gradients, no glassmorphism; visible focus rings
// and WCAG AA contrast throughout.
function impeccableShell(title, bodyHtml) {
  return [
    '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<title>', title, ' · DeepSeek Harness</title>',
    '<style>',
    ':root{--lacquer:#0b0a08;--panel:#131110;--panel2:#1a1714;--gold:#e2b961;--gold-hover:#ecc87c;--ink:#ece6da;--muted:#9b9184;--faint:#6f675c;--hairline:rgba(226,185,97,.16);--err:#e0877a;--errbg:rgba(224,135,122,.10);--ok:#9cc9ab;--okbg:rgba(156,201,171,.10)}',
    '*{box-sizing:border-box}',
    'body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;background:radial-gradient(1100px 700px at 50% -8%,#181410 0%,var(--lacquer) 58%);color:var(--ink);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}',
    '.card{width:100%;max-width:400px;background:var(--panel);border:1px solid var(--hairline);border-radius:16px;padding:40px 34px;box-shadow:0 24px 80px rgba(0,0,0,.55)}',
    '.brand{display:flex;align-items:center;gap:13px;margin-bottom:8px}',
    '.logo{width:40px;height:40px;border-radius:11px;background:var(--gold);color:#171310;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:21px}',
    '.brand h1{font-size:20px;margin:0;font-weight:650;letter-spacing:.2px}',
    '.brand .sub{font-size:12px;color:var(--muted);margin-top:2px;letter-spacing:.4px}',
    'p.lead{color:var(--muted);font-size:13px;margin:10px 0 24px;line-height:1.65}',
    'label{display:block;font-size:12.5px;color:var(--muted);margin:16px 0 7px;letter-spacing:.3px}',
    'input{width:100%;background:var(--panel2);border:1px solid var(--hairline);border-radius:10px;color:var(--ink);padding:12px 14px;font-size:14.5px;outline:none}',
    'input:focus{border-color:var(--gold);box-shadow:0 0 0 3px rgba(226,185,97,.18)}',
    'button{margin-top:26px;width:100%;background:var(--gold);border:0;border-radius:10px;color:#171310;font-size:14.5px;font-weight:650;padding:12px;cursor:pointer;letter-spacing:.3px}',
    'button:hover{background:var(--gold-hover)}',
    'button:disabled{opacity:.55;cursor:not-allowed}',
    'button:focus-visible{outline:2px solid var(--gold);outline-offset:2px}',
    '.msg{display:none;margin-top:18px;padding:11px 13px;border-radius:9px;font-size:13px;line-height:1.5}',
    '.msg.err{display:block;background:var(--errbg);color:var(--err);border:1px solid rgba(224,135,122,.28)}',
    '.msg.ok{display:block;background:var(--okbg);color:var(--ok);border:1px solid rgba(156,201,171,.28)}',
    '.rule{height:1px;background:var(--hairline);margin:22px 0 14px}',
    '.hint{font-size:12.5px;color:var(--faint);line-height:1.7}',
    'code{background:var(--panel2);border:1px solid var(--hairline);padding:2px 6px;border-radius:6px;font-size:12px;color:var(--gold)}',
    '</style></head><body>',
    bodyHtml,
    '</body></html>',
  ].join('');
}

function loginPage(csrf, error) {
  const errDiv = error ? '<div class="msg err" id="msg"></div>' : '<div class="msg" id="msg"></div>';
  const body = [
    '<div class="card"><div class="brand"><div class="logo">D</div><div><h1>DeepSeek Harness</h1><div class="sub">登录控制台</div></div></div>',
    '<p class="lead">请输入你的账号与密码以继续。账号由服务器管理员创建。</p>',
    '<form id="f" method="post" action="/login" autocomplete="on">',
    '<input type="hidden" name="csrf" value="' + csrf + '">',
    '<label for="u">用户名</label><input id="u" name="username" type="text" autocomplete="username" required autofocus>',
    '<label for="p">密码</label><input id="p" name="password" type="password" autocomplete="current-password" required>',
    '<button type="submit" id="btn">登录</button>',
    '</form>', errDiv,
    '<div class="rule"></div>',
    '<div class="hint">忘记密码？请联系服务器管理员重置。</div>',
    '</div>',
    '<script>',
    'var m=document.getElementById("msg");',
    error ? 'm.className="msg err";m.textContent=' + JSON.stringify(error) + ';' : '',
    'document.getElementById("f").addEventListener("submit",function(){var b=document.getElementById("btn");if(b){b.disabled=true;b.textContent="登录中…";}});',
    '</scr' + 'ipt>',
  ].join('');
  return impeccableShell('登录', body);
}

function setupPage(csrf, error, warning) {
  const msgDiv = error ? '<div class="msg err" id="msg"></div>' : '<div class="msg" id="msg"></div>';
  const body = [
    '<div class="card"><div class="brand"><div class="logo">D</div><div><h1>DeepSeek Harness</h1><div class="sub">API Key 配置</div></div></div>',
    '<p class="lead">你的账户尚未配置 DeepSeek API Key。请粘贴你的 Key 以启用 AI 功能。</p>',
    '<form id="f" method="post" action="/setup" autocomplete="off">',
    '<input type="hidden" name="csrf" value="' + csrf + '">',
    '<label for="k">DeepSeek API Key</label><input id="k" name="key" type="password" autocomplete="off" placeholder="sk-..." required>',
    '<button type="submit" id="btn">保存并继续</button>',
    '</form>', msgDiv,
    '<div class="rule"></div>',
    '<div class="hint">可在 <code>platform.deepseek.com</code> → API Keys 创建 Key。Key 仅保存在你的私有目录中，仅你本人可用。</div>',
    '</div>',
    '<script>',
    'var m=document.getElementById("msg");',
    error ? 'm.className="msg err";m.textContent=' + JSON.stringify(error) + ';' : '',
    warning ? 'm.className="msg ok";m.textContent=' + JSON.stringify(warning) + ';' : '',
    'document.getElementById("f").addEventListener("submit",function(){var b=document.getElementById("btn");if(b){b.disabled=true;b.textContent="保存中…";}});',
    '</scr' + 'ipt>',
  ].join('');
  return impeccableShell('配置 API Key', body);
}

function json(res, code, obj) {
  secHeaders(res);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}
function redirect(res, loc) {
  res.writeHead(302, { Location: loc, 'Cache-Control': 'no-store' });
  res.end();
}

// ---------- user file browser & download (deliverables) ----------
// User homes are 0700 owned by their dsh-<name> account; userctl grants the
// gateway service account an ACL (u:ubuntu:rX + default) so this authenticated
// web layer can list and download the files agents produce.
const DL_MIME = {
  '.txt': 'text/plain; charset=utf-8', '.md': 'text/plain; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.csv': 'text/csv; charset=utf-8',
  '.log': 'text/plain; charset=utf-8', '.html': 'text/plain; charset=utf-8',
  '.js': 'text/plain; charset=utf-8', '.css': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp',
  '.pdf': 'application/pdf', '.zip': 'application/zip',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};
function dlContentType(name) { return DL_MIME[path.extname(String(name)).toLowerCase()] || 'application/octet-stream'; }
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
function fmtSize(n) {
  if (!Number.isFinite(n) || n < 0) return '';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
  return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}
function userHome(user) {
  const u = getUser(user);
  return (u && u.home) || path.join(USERS_DIR, user);
}

// In-page deliverables widgets injected into the SPA shell: two draggable
// capsule buttons (交付文件 / 上传文件) each opening its own restrained white
// drawer (light paper/ink tokens, per the impeccable design reference). No
// page navigation; embedded pages close the drawer via postMessage. No
// backdrop blur or gradient chrome; focus rings, ESC/backdrop close,
// reduced-motion respected.
const FILES_LINK_HTML = [
  '<style>',
  '#dshgw-fab-stack{position:fixed;right:20px;bottom:20px;z-index:2147483000;display:flex;flex-direction:column;gap:10px;align-items:flex-end;touch-action:none;user-select:none}',
  '.dshgw-fab{display:inline-flex;align-items:center;gap:8px;background:#fcfcfd;color:#1e293b;border:1px solid #e2e8f0;font:600 13px/1.2 -apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;padding:10px 16px;border-radius:999px;box-shadow:0 1px 2px rgba(16,24,40,.06),0 4px 12px rgba(16,24,40,.08);cursor:grab;transition:box-shadow .16s ease,transform .16s ease}',
  '.dshgw-fab:hover{box-shadow:0 2px 4px rgba(16,24,40,.08),0 8px 20px rgba(16,24,40,.14);transform:translateY(-1px)}',
  '.dshgw-fab:active{cursor:grabbing}',
  '.dshgw-fab:focus-visible{outline:2px solid #2563eb;outline-offset:2px}',
  '#dshgw-fab-stack.dragging .dshgw-fab{transition:none;box-shadow:0 4px 8px rgba(16,24,40,.10),0 16px 36px rgba(16,24,40,.18)}',
  '.dshgw-ov{display:none;position:fixed;inset:0;z-index:2147483100;background:rgba(16,24,40,.45);align-items:center;justify-content:center;padding:24px}',
  '.dshgw-ov.open{display:flex}',
  '.dshgw-panel{position:relative;width:min(900px,100%);height:min(82vh,760px);background:#fcfcfd;border:1px solid #e2e8f0;border-radius:16px;box-shadow:0 1px 2px rgba(16,24,40,.06),0 8px 24px rgba(16,24,40,.12),0 32px 80px rgba(16,24,40,.18);overflow:hidden;display:flex;flex-direction:column;opacity:0;transform:translateY(10px) scale(.985);transition:opacity .18s ease,transform .18s ease}',
  '.dshgw-panel.small{width:min(560px,100%);height:min(70vh,620px)}',
  '.dshgw-ov.open .dshgw-panel{opacity:1;transform:none}',
  '.dshgw-x{position:absolute;top:10px;right:10px;z-index:2;width:32px;height:32px;border-radius:10px;border:0;background:#f1f5f9;color:#475569;font:500 18px/1 -apple-system,"Segoe UI",sans-serif;cursor:pointer;display:flex;align-items:center;justify-content:center}',
  '.dshgw-x:hover{background:#e2e8f0;color:#0f172a}',
  '.dshgw-x:focus-visible{outline:2px solid #2563eb;outline-offset:2px}',
  '.dshgw-frame{flex:1;width:100%;border:0;background:#fcfcfd}',
  '@media (prefers-reduced-motion: reduce){.dshgw-fab,.dshgw-panel{transition:none}}',
  '</style>',
  '<div id="dshgw-fab-stack">',
  '  <button class="dshgw-fab" id="dshgw-fab-files" type="button" aria-haspopup="dialog" title="浏览并下载当前工作区的交付文件">&#128229; 交付文件</button>',
  '  <button class="dshgw-fab" id="dshgw-fab-up" type="button" aria-haspopup="dialog" title="上传文件到当前工作区">&#128228; 上传文件</button>',
  '</div>',
  '<div class="dshgw-ov" id="dshgw-ov-files" role="dialog" aria-modal="true" aria-label="交付文件">',
  '  <div class="dshgw-panel">',
  '    <button class="dshgw-x" type="button" aria-label="关闭">&#215;</button>',
  '    <iframe class="dshgw-frame" title="交付文件" src="about:blank"></iframe>',
  '  </div>',
  '</div>',
  '<div class="dshgw-ov" id="dshgw-ov-up" role="dialog" aria-modal="true" aria-label="上传文件">',
  '  <div class="dshgw-panel small">',
  '    <button class="dshgw-x" type="button" aria-label="关闭">&#215;</button>',
  '    <iframe class="dshgw-frame" title="上传文件" src="about:blank"></iframe>',
  '  </div>',
  '</div>',
  '<script>',
  '(function(){',
  'var stack=document.getElementById("dshgw-fab-stack");',
  'var fabs=[document.getElementById("dshgw-fab-files"),document.getElementById("dshgw-fab-up")];',
  'var ovs=[document.getElementById("dshgw-ov-files"),document.getElementById("dshgw-ov-up")];',
  'var frames=[ovs[0].querySelector("iframe"),ovs[1].querySelector("iframe")];',
  'var loaded=[false,false],srcs=["/__gw/files?embed=1","/__gw/upload?embed=1"];',
  'var moved=false;',
  'function open(i){if(moved){moved=false;return;}if(!loaded[i]){frames[i].src=srcs[i];loaded[i]=true;}ovs[i].classList.add("open");ovs[i].querySelector(".dshgw-x").focus();}',
  'function shutAll(){ovs.forEach(function(o){o.classList.remove("open");});}',
  'fabs[0].addEventListener("click",function(){open(0);});',
  'fabs[1].addEventListener("click",function(){open(1);});',
  'ovs.forEach(function(o){var x=o.querySelector(".dshgw-x");x.addEventListener("click",shutAll);o.addEventListener("click",function(e){if(e.target===o)shutAll();});});',
  'document.addEventListener("keydown",function(e){if(e.key==="Escape")shutAll();});',
  'window.addEventListener("message",function(e){if(e.data==="dshgw-close")shutAll();if(e.data==="dshgw-open-files")open(0);});',
  'var dragging=false,sx=0,sy=0,ox=0,oy=0,posKey="dshgw-fab-pos-v1";',
  'try{var saved=JSON.parse(localStorage.getItem(posKey)||"null");if(saved&&typeof saved.x==="number"&&typeof saved.y==="number"){stack.style.right="auto";stack.style.bottom="auto";stack.style.left=saved.x+"px";stack.style.top=saved.y+"px";}}catch(e){}',
  'stack.addEventListener("pointerdown",function(ev){if(ev.button!==0)return;dragging=true;moved=false;sx=ev.clientX;sy=ev.clientY;var r=stack.getBoundingClientRect();ox=r.left;oy=r.top;stack.classList.add("dragging");});',
  'document.addEventListener("pointermove",function(ev){if(!dragging)return;var dx=ev.clientX-sx,dy=ev.clientY-sy;if(!moved&&Math.abs(dx)<6&&Math.abs(dy)<6)return;moved=true;var w=window.innerWidth,h=window.innerHeight,r=stack.getBoundingClientRect();var nx=Math.max(8,Math.min(ox+dx,w-r.width-8)),ny=Math.max(8,Math.min(oy+dy,h-r.height-8));stack.style.right="auto";stack.style.bottom="auto";stack.style.left=nx+"px";stack.style.top=ny+"px";});',
  'document.addEventListener("pointerup",function(){if(!dragging)return;dragging=false;stack.classList.remove("dragging");if(moved){var r=stack.getBoundingClientRect();try{localStorage.setItem(posKey,JSON.stringify({x:Math.round(r.left),y:Math.round(r.top)}));}catch(e){}}});',
  '})();',
  '</scr' + 'ipt>',
].join('');

// ---------- reverse proxy ----------
const HOP = new Set(['connection', 'proxy-connection', 'keep-alive', 'transfer-encoding', 'te', 'trailer', 'upgrade', 'proxy-authorization', 'proxy-authenticate', 'content-length']);
function cleanHeaders(h) {
  const out = {};
  for (const k in h) {
    if (HOP.has(String(k).toLowerCase())) continue;
    out[k] = h[k];
  }
  return out;
}
// Rewrite the request so the per-user backend sees a loopback client. DSH pins
// privileged methods (settings/credentials/agentPreset/llm.discoverModels) to
// loopback-only; the gateway is the authenticated front door on the same host,
// so present Host=127.0.0.1:<port> and drop browser-trust markers.
function backendHeaders(req, port) {
  const headers = cleanHeaders(req.headers);
  delete headers['cookie'];
  delete headers['x-forwarded-for'];
  delete headers['x-forwarded-proto'];
  delete headers['x-forwarded-host'];
  headers['host'] = '127.0.0.1:' + port;
  delete headers['origin'];
  delete headers['referer'];
  delete headers['sec-fetch-site'];
  delete headers['sec-fetch-mode'];
  delete headers['sec-fetch-dest'];
  delete headers['sec-fetch-user'];
  headers['x-forwarded-for'] = clientIp(req);
  headers['x-forwarded-proto'] = 'https';
  return headers;
}
// ---------- current-workspace tracking ----------
// The SPA reports the active conversation through proxied RPCs: the gateway
// watches `sessions.history` (open) requests and `sessions.list` responses to
// remember each user's current cwd, so the deliverables drawers open there.
const CWD_STATE_FILE = process.env.CWD_STATE_FILE || '/opt/deepseek-harness/gateway/state-cwd.json';
const cwdTrack = new Map(); // user -> { currentId, idToCwd: Map, cwd, at }
try {
  const loaded = JSON.parse(fs.readFileSync(CWD_STATE_FILE, 'utf8'));
  for (const u of Object.keys(loaded || {})) {
    const e = loaded[u];
    if (e && typeof e.cwd === 'string') cwdTrack.set(u, { currentId: null, idToCwd: new Map(), cwd: e.cwd, at: e.at || 0 });
  }
} catch (e) {}
let cwdSaveTimer = null;
function scheduleCwdPersist() {
  if (cwdSaveTimer) return;
  cwdSaveTimer = setTimeout(() => {
    cwdSaveTimer = null;
    const out = {};
    for (const [u, e] of cwdTrack) if (e.cwd) out[u] = { cwd: e.cwd, at: e.at };
    try { fs.writeFileSync(CWD_STATE_FILE, JSON.stringify(out) + '\n', { mode: 0o600 }); } catch (e) {}
  }, 5000);
}
function rememberCurrentSession(user, sessionId) {
  let e = cwdTrack.get(user);
  if (!e) { e = { currentId: null, idToCwd: new Map(), cwd: null, at: 0 }; cwdTrack.set(user, e); }
  e.currentId = sessionId;
  const cwd = e.idToCwd.get(sessionId);
  if (cwd) { e.cwd = cwd; e.at = Date.now(); scheduleCwdPersist(); }
}
function feedSessionList(user, items) {
  if (!Array.isArray(items) || !user) return;
  let e = cwdTrack.get(user);
  if (!e) { e = { currentId: null, idToCwd: new Map(), cwd: null, at: 0 }; cwdTrack.set(user, e); }
  let newest = null;
  for (const it of items) {
    if (!it || typeof it.sessionId !== 'string') continue;
    if (typeof it.cwd === 'string' && it.cwd) e.idToCwd.set(it.sessionId, it.cwd);
    if (!newest || (typeof it.updatedAt === 'number' && (typeof newest.updatedAt !== 'number' || it.updatedAt > newest.updatedAt))) newest = it;
  }
  let resolved = null;
  if (e.currentId && e.idToCwd.has(e.currentId)) resolved = e.idToCwd.get(e.currentId);
  if (!resolved && newest && typeof newest.cwd === 'string' && newest.cwd) resolved = newest.cwd;
  if (resolved && resolved !== e.cwd) {
    e.cwd = resolved;
    e.at = Date.now();
    scheduleCwdPersist();
    console.log('cwd-track ' + user + ' -> ' + resolved);
  }
}
function currentCwd(user) {
  const e = cwdTrack.get(user);
  return (e && e.cwd) || null;
}

const HISTORY_MESSAGE_TYPES = new Set(['user/message', 'assistant/message']);
// Returns { events, hasMore } when the page was trimmed, otherwise null.
function trimHistoryValue(value) {
  if (!value || !Array.isArray(value.events) || value.events.length <= HISTORY_TRIM_MIN_EVENTS) return null;
  const events = value.events;
  for (const item of events) {
    if (!item || !item.event || typeof item.event.seq !== 'number') return null;
  }
  const kept = [];
  let count = 0;
  let trimmed = false;
  for (let i = events.length - 1; i >= 0; i--) {
    const ev = events[i].event;
    if (HISTORY_MESSAGE_TYPES.has(ev.type) && ev.surfaceOp === 'append') count++;
    if (count >= HISTORY_TRIM_MESSAGES) {
      const sources = (Array.isArray(ev.sourceEventSeqs) ? ev.sourceEventSeqs : []).filter((s) => typeof s === 'number');
      const groupStart = Math.min(ev.seq, ...sources);
      for (let j = i; j >= 0 && events[j].event.seq >= groupStart; j--) kept.push(events[j]);
      trimmed = true;
      break;
    }
    kept.push(events[i]);
  }
  if (!trimmed) return null;
  kept.reverse();
  return { events: kept, hasMore: true };
}
function gzipBodyIfWanted(req, upstreamHeaders, body) {
  const ae = String(req.headers['accept-encoding'] || '');
  if (/\bgzip\b/.test(ae) && !upstreamHeaders['content-encoding'] && body.length >= GZIP_MIN_BYTES) {
    try { return zlib.gzipSync(body, { level: 4 }); } catch (e) {}
  }
  return null;
}
function setGzipHeaders(h) {
  const out = Object.assign({}, h);
  delete out['content-length'];
  out['content-encoding'] = 'gzip';
  const v = String(out['vary'] || '');
  out['vary'] = v.indexOf('Accept-Encoding') >= 0 ? v : (v ? v + ', ' : '') + 'Accept-Encoding';
  return out;
}

function proxyRequest(req, res, port, user) {
  const headers = backendHeaders(req, port);
  const qIdx = req.url.indexOf('?');
  const reqPath = qIdx < 0 ? req.url : req.url.slice(0, qIdx);
  // DSH client RPC paths are singular: /api/session.list, /api/session.history.
  const sniffHistoryReq = req.method === 'POST' && reqPath === '/api/session.history' && !!user;
  const sniffHistoryRes = sniffHistoryReq;
  const sniffListRes = req.method === 'POST' && reqPath === '/api/session.list' && !!user;
  const upstreamReq = http.request({
    host: '127.0.0.1',
    port: port,
    method: req.method,
    path: req.url,
    headers: headers,
  }, (upstreamRes) => {
    const rh = cleanHeaders(upstreamRes.headers);
    const ct = String(upstreamRes.headers['content-type'] || '');
    const canInject = req.method === 'GET' && ct.indexOf('text/html') === 0 && !upstreamRes.headers['content-encoding'];
    const wantJsonGzip = /\bgzip\b/.test(String(req.headers['accept-encoding'] || '')) && !upstreamRes.headers['content-encoding'] && ct.indexOf('application/json') === 0;
    const needBuffer = canInject || sniffListRes || sniffHistoryRes;
    if (!needBuffer) {
      upstreamRes.on('error', () => { try { res.destroy(); } catch (e) {} });
      if (wantJsonGzip) {
        const gz = zlib.createGzip({ level: 4 });
        gz.on('error', () => { try { res.destroy(); } catch (e) {} });
        res.writeHead(upstreamRes.statusCode || 502, setGzipHeaders(rh));
        upstreamRes.pipe(gz).pipe(res);
      } else {
        res.writeHead(upstreamRes.statusCode || 502, rh);
        upstreamRes.pipe(res);
      }
      return;
    }
    // Buffer small bodies: SPA HTML for injection, session lists for cwd
    // tracking, session history for page trimming. Oversized bodies fall
    // back to a plain untouched stream.
    const MAX_BUF = sniffHistoryRes ? HISTORY_BUF_MAX : 8 * 1024 * 1024;
    let buf = [];
    let size = 0;
    let settled = false;
    upstreamRes.on('data', (c) => {
      if (settled) return;
      size += c.length;
      if (size > MAX_BUF) {
        settled = true;
        res.writeHead(upstreamRes.statusCode || 502, rh);
        for (const b of buf) res.write(b);
        buf = [];
        upstreamRes.pipe(res);
      } else {
        buf.push(c);
      }
    });
    upstreamRes.on('end', () => {
      if (settled) return;
      settled = true;
      let body = Buffer.concat(buf);
      let outHeaders = rh;
      if (sniffListRes) {
        try {
          const j = JSON.parse(body.toString('utf8'));
          feedSessionList(user, j && j.result && j.result.value && j.result.value.items);
        } catch (e) {}
      } else if (sniffHistoryRes) {
        try {
          const j = JSON.parse(body.toString('utf8'));
          const v = j && j.result && j.result.value;
          const t = trimHistoryValue(v);
          if (t) {
            v.events = t.events;
            v.hasMore = t.hasMore;
            body = Buffer.from(JSON.stringify(j), 'utf8');
            console.log('history-trim ' + user + ' kept ' + t.events.length + ' events');
          }
        } catch (e) {}
      } else {
        let html = body.toString('utf8');
        const at = html.toLowerCase().lastIndexOf('</body>');
        html = at >= 0 ? html.slice(0, at) + FILES_LINK_HTML + html.slice(at) : html + FILES_LINK_HTML;
        body = Buffer.from(html, 'utf8');
      }
      if (wantJsonGzip) {
        const gz = gzipBodyIfWanted(req, upstreamRes.headers, body);
        if (gz) { body = gz; outHeaders = setGzipHeaders(outHeaders); }
      }
      res.writeHead(upstreamRes.statusCode || 502, outHeaders);
      res.end(body);
    });
    upstreamRes.on('error', () => {
      if (!settled) { settled = true; if (!res.headersSent) { try { res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' }); } catch (e) {} } }
      try { res.destroy(); } catch (e) {}
    });
    upstreamRes.on('aborted', () => { try { res.destroy(); } catch (e) {} });
  });
  upstreamReq.on('error', (e) => {
    console.error('proxy error ->', port, e.message);
    if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Bad Gateway: 后端服务不可用');
  });
  req.on('error', () => upstreamReq.destroy());
  res.on('error', () => upstreamReq.destroy());
  res.on('close', () => { try { upstreamReq.destroy(); } catch (e) {} });
  if (sniffHistoryReq) {
    readBodyBuf(req, 256 * 1024).then((body) => {
      try {
        const j = JSON.parse(body.toString('utf8'));
        const sid = j && j.payload && j.payload.sessionId;
        if (typeof sid === 'string' && sid) rememberCurrentSession(user, sid);
      } catch (e) {}
      upstreamReq.write(body);
      upstreamReq.end();
    }).catch(() => { try { upstreamReq.destroy(); } catch (e) {} });
    return;
  }
  req.pipe(upstreamReq);
}
function proxyUpgrade(req, socket, head, port) {
  const headers = backendHeaders(req, port);
  const lines = [req.method + ' ' + req.url + ' HTTP/1.1'];
  for (const k in headers) {
    const v = headers[k];
    if (Array.isArray(v)) lines.push(k + ': ' + v.join(', '));
    else lines.push(k + ': ' + v);
  }
  lines.push('Connection: Upgrade');
  lines.push('Upgrade: websocket');
  lines.push('', '');
  const raw = lines.join('\r\n');
  const upstream = net.connect(port, '127.0.0.1', () => {
    upstream.write(raw);
    if (head && head.length) upstream.write(head);
    socket.pipe(upstream);
    upstream.pipe(socket);
  });
  upstream.on('error', () => socket.destroy());
  socket.on('error', () => upstream.destroy());
  socket.on('close', () => upstream.destroy());
  upstream.on('close', () => socket.destroy());
}

// ---------- request logging ----------
function logLine(req, status, extra) {
  console.log(new Date().toISOString() + ' ' + clientIp(req) + ' ' + req.method + ' ' + req.url + ' ' + status + (extra ? ' ' + extra : ''));
}

// ---------- server ----------
// App-level static assets served without auth (identical across instances).
const STATIC_ASSETS = {
  '/manifest.webmanifest': { file: path.join(__dirname, 'static', 'manifest.webmanifest'), type: 'application/manifest+json' },
  '/favicon.svg': { file: path.join(__dirname, 'static', 'favicon.svg'), type: 'image/svg+xml' },
};

const server = http.createServer(async (req, res) => {
  const q = req.url.indexOf('?');
  const pathname = q < 0 ? req.url : req.url.slice(0, q);
  const session = getSession(req);

  if (req.method === 'GET' && STATIC_ASSETS[pathname]) {
    const asset = STATIC_ASSETS[pathname];
    try {
      const data = fs.readFileSync(asset.file);
      res.writeHead(200, { 'Content-Type': asset.type, 'Cache-Control': 'no-cache' });
      return res.end(data);
    } catch (e) { /* fall through to normal handling */ }
  }

  if (pathname === '/__gw/health') return json(res, 200, { ok: true, now: Date.now() });

  if (pathname === '/__gw/status') {
    if (!session) return json(res, 401, { ok: false, user: null });
    return json(res, 200, { ok: true, user: session.u, keyConfigured: hasKey(session.u) });
  }

  if (pathname === '/login') {
    if (req.method === 'GET') {
      if (session) return redirect(res, hasKey(session.u) ? '/' : '/setup');
      const csrf = crypto.randomBytes(16).toString('hex');
      res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf, { maxAge: 600, path: '/', sameSite: 'Lax' }));
      secHeaders(res);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(loginPage(csrf, null));
    }
    if (req.method === 'POST') {
      let body;
      try { body = await readBody(req, 10000); } catch (e) { return json(res, 413, { ok: false, error: '请求过大' }); }
      const form = parseForm(body);
      const cookies = parseCookies(req);
      if (!form.csrf || !cookies[CSRF_COOKIE] || !timingSafeStr(form.csrf, cookies[CSRF_COOKIE])) {
        logLine(req, 403, 'csrf');
        const csrf2 = crypto.randomBytes(16).toString('hex');
        res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf2, { maxAge: 600, path: '/', sameSite: 'Lax' }));
        secHeaders(res);
        res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(loginPage(csrf2, 'CSRF 校验失败，请刷新页面重试'));
      }
      const username = (form.username || '').trim();
      const password = form.password || '';
      const attempt = checkAttempts(req, username);
      if (!attempt.allowed) {
        res.setHeader('Retry-After', String(attempt.retryAfter));
        logLine(req, 429, 'locked ' + username);
        const csrf2 = crypto.randomBytes(16).toString('hex');
        res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf2, { maxAge: 600, path: '/', sameSite: 'Lax' }));
        secHeaders(res);
        res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(loginPage(csrf2, '尝试次数过多，请 ' + attempt.retryAfter + ' 秒后重试'));
      }
      const u = getUser(username);
      if (!u || !u.pwd || !verifyPassword(password, u.pwd)) {
        recordFailure(req, username);
        logLine(req, 401, 'bad-creds ' + username);
        const csrf2 = crypto.randomBytes(16).toString('hex');
        res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf2, { maxAge: 600, path: '/', sameSite: 'Lax' }));
        secHeaders(res);
        res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(loginPage(csrf2, '用户名或密码错误'));
      }
      recordSuccess(req, username);
      setSession(res, username);
      logLine(req, 302, 'login ' + username);
      return redirect(res, hasKey(username) ? '/' : '/setup');
    }
    return json(res, 405, { ok: false, error: '方法不允许' });
  }

  if (pathname === '/logout') {
    clearSession(res);
    return redirect(res, '/login');
  }

  if (pathname === '/setup') {
    if (!session) return redirect(res, '/login');
    if (hasKey(session.u)) return redirect(res, '/');
    if (req.method === 'GET') {
      secHeaders(res);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(setupPage(session.n, null, null));
    }
    if (req.method === 'POST') {
      let body;
      try { body = await readBody(req, 10000); } catch (e) { return json(res, 413, { ok: false, error: '请求过大' }); }
      const form = parseForm(body);
      const renderErr = (msg) => {
        secHeaders(res);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(setupPage(session.n, msg, null));
      };
      if (!form.csrf || !timingSafeStr(form.csrf, session.n)) {
        logLine(req, 403, 'csrf-setup');
        return renderErr('CSRF 校验失败，请刷新页面重试');
      }
      const key = (form.key || '').trim();
      if (!/^sk-[A-Za-z0-9_-]{8,}$/.test(key)) {
        return renderErr('Key 格式不正确（应以 sk- 开头）');
      }
      const v = await validateKey(key, 8000);
      if (!v.ok) return renderErr(v.detail || 'Key 校验失败');
      const u = getUser(session.u);
      if (!u || !u.port) return renderErr('账号配置异常');
      const saved = await rpcCredentialsSet(u.port, key);
      if (!saved.ok) return renderErr('写入失败：' + saved.detail);
      setUserKeyFlag(session.u, true);
      logLine(req, 200, 'set-key ' + session.u);
      return redirect(res, '/');
    }
    return json(res, 405, { ok: false, error: '方法不允许' });
  }

  if (pathname === '/__gw/upload') {
    if (req.method === 'GET') {
      if (!session) return redirect(res, '/login');
      if (!hasKey(session.u)) return redirect(res, '/setup');
      const home = userHome(session.u);
      if (!home) {
        clearSession(res);
        return json(res, 401, { ok: false, error: '账号不可用' });
      }
      let q = {};
      try { q = Object.fromEntries(new URL(req.url, 'http://gw').searchParams.entries()); } catch (e) {}
      const embed = String(q.embed || '') === '1';
      // Target directory: explicit ?dir=, else the tracked conversation cwd,
      // else the workspace default (canonicalized by the list helper).
      let target = String(q.dir || '') || currentCwd(session.u) || '';
      let display = home;
      try {
        const out = execFileSync('sudo', ['-n', FILE_LIST_HELPER, home, target], { timeout: 15000, maxBuffer: 8 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }).toString('utf8');
        display = JSON.parse(out).dir;
      } catch (e) {
        try {
          const out2 = execFileSync('sudo', ['-n', FILE_LIST_HELPER, home, ''], { timeout: 15000, maxBuffer: 8 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }).toString('utf8');
          display = JSON.parse(out2).dir;
        } catch (e2) {}
      }
      const body = [
        '<div class="dlcard' + (embed ? ' embed' : '') + '">',
        '<div class="dlhead"><div><h1>&#128228; 上传文件</h1><p class="sub">文件将上传到你的当前工作目录；在对话中打开时，会自动定位到该对话所在的工作区。</p></div>',
        '<a class="ghost" href="/" id="backbtn">返回应用</a>',
        '</div>',
        '<div class="target">当前目录<span class="tpath">' + esc(display) + '</span></div>',
        '<div class="upbar"><input type="file" id="upfile" multiple><button type="button" id="upbtn">上传</button></div>',
        '<div class="upmsg" id="upmsg"></div>',
        '<div class="uplist" id="uplist"></div>',
        '<div class="afters" id="afters" style="display:none"><a class="ghost" id="viewbtn" href="/__gw/files">查看交付文件</a></div>',
        '<script>',
        'function backToApp(){if(window.parent!==window){try{parent.postMessage("dshgw-close","*");}catch(e){location.href="/";}}else{location.href="/";}}document.getElementById("backbtn").addEventListener("click",function(e){e.preventDefault();backToApp();});',
        (embed ? 'document.getElementById("viewbtn").addEventListener("click",function(e){e.preventDefault();parent.postMessage("dshgw-open-files","*");});' : ''),
        '(function(){var dir=' + JSON.stringify(display).replace(/</g, '\\u003c') + ';var f=document.getElementById("upfile");var b=document.getElementById("upbtn");var m=document.getElementById("upmsg");var ul=document.getElementById("uplist");var done=document.getElementById("afters");',
        'b.addEventListener("click",function(){if(!f.files||f.files.length===0){m.textContent="请先选择文件";return;}var files=Array.prototype.slice.call(f.files);var i=0,ok=0,fail=0;ul.textContent="";m.textContent="";',
        'function next(){if(i>=files.length){m.textContent="完成："+ok+" 个成功"+(fail?"，"+fail+" 个失败":"");if(ok>0)done.style.display="block";return;}var file=files[i];m.textContent="上传中 "+(i+1)+"/"+files.length+"："+file.name;',
        'fetch("/__gw/upload?dir="+encodeURIComponent(dir)+"&name="+encodeURIComponent(file.name),{method:"POST",body:file}).then(function(r){return r.json().catch(function(){return {};}).then(function(j){if(!r.ok)throw new Error(j.error||("HTTP "+r.status));});}).then(function(){var li=document.createElement("div");li.className="uok";li.textContent="✓ "+file.name;ul.appendChild(li);ok++;i++;next();}).catch(function(e){var li=document.createElement("div");li.className="ufail";li.textContent="✕ "+file.name+"："+(e&&e.message?e.message:e);ul.appendChild(li);fail++;i++;next();});}',
        'next();});})();',
        '</scr' + 'ipt>',
        '<style>',
        'body{background:#f6f8fa}',
        '.dlcard{width:100%;max-width:600px;background:#fcfcfd;border:1px solid #e2e8f0;border-radius:14px;padding:24px 26px;box-shadow:0 1px 2px rgba(16,24,40,.05),0 12px 32px rgba(16,24,40,.10)}',
        '.dlcard.embed{max-width:none;width:100%;border:0;border-radius:0;box-shadow:none;padding:18px 22px 24px;min-height:100%;box-sizing:border-box}',
        '.dlhead{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:16px}',
        '.dlcard.embed .dlhead{padding-right:44px}',
        '.dlhead h1{font-size:17px;font-weight:650;margin:0;color:#0f172a;letter-spacing:.2px}',
        '.dlhead .sub{font-size:13px;color:#64748b;margin:6px 0 0;max-width:520px;line-height:1.55}',
        '.ghost{white-space:nowrap;color:#2563eb;text-decoration:none;font-size:13px;padding:8px 14px;border:1px solid #e2e8f0;border-radius:10px;background:#fff;cursor:pointer;margin-top:0;width:auto}',
        '.ghost:hover{background:#f1f5f9}',
        '.target{font-size:12.5px;color:#64748b;margin-bottom:12px;display:flex;align-items:center;gap:8px}',
        '.tpath{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:#334155;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:5px 10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}',
        '.upbar{display:flex;gap:10px;align-items:center;margin-bottom:10px}',
        '.upbar input[type=file]{flex:1;width:auto;background:#f8fafc;border:1px dashed #cbd5e1;border-radius:10px;color:#64748b;font-size:12.5px;padding:9px 12px}',
        '.upbar input[type=file]:focus-visible{outline:2px solid #2563eb;outline-offset:2px}',
        '.upbar button{margin-top:0;width:auto;padding:9px 18px;font-size:13px;font-weight:600;background:#2563eb;color:#fff;border-radius:10px}',
        '.upbar button:hover{filter:none;background:#1d4ed8}',
        '.upbar button:focus-visible{outline:2px solid #2563eb;outline-offset:2px}',
        '.upmsg{font-size:12.5px;color:#64748b;margin:0 0 10px;min-height:16px}',
        '.uplist{display:flex;flex-direction:column;gap:6px;margin-bottom:12px}',
        '.uok,.ufail{font-size:13px;padding:8px 12px;border-radius:8px}',
        '.uok{color:#15803d;background:#f0fdf4;border:1px solid #bbf7d0}',
        '.ufail{color:#b91c1c;background:#fef2f2;border:1px solid #fecaca}',
        '.afters{margin-top:4px}',
        (embed ? 'body{background:#fcfcfd;padding:0;align-items:stretch}' : ''),
        '</style>',
        '</div>',
      ].join('');
      secHeaders(res);
      res.setHeader('X-Frame-Options', 'SAMEORIGIN');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(htmlShell('上传文件', body));
    }
    if (req.method !== 'POST') return json(res, 405, { ok: false, error: '方法不允许' });
    if (!session) return json(res, 401, { ok: false, error: '未登录' });
    if (!hasKey(session.u)) return json(res, 403, { ok: false, error: '请先配置 API Key', redirect: '/setup' });
    const home = userHome(session.u);
    if (!home) {
      clearSession(res);
      return json(res, 401, { ok: false, error: '账号不可用' });
    }
    let q = {};
    try { q = Object.fromEntries(new URL(req.url, 'http://gw').searchParams.entries()); } catch (e) {}
    const dir = String(q.dir || '');
    const name = String(q.name || '');
    if (!dir) return json(res, 400, { ok: false, error: '缺少 dir 参数' });
    const dirAbs = path.resolve(dir);
    if (!name || name.length > 200 || name.indexOf('\0') >= 0 || /[\/\\]/.test(name) || name === '.' || name === '..' || name.startsWith('.') || /[\x00-\x1f\x7f]/.test(name)) {
      return json(res, 400, { ok: false, error: '文件名不合法' });
    }
    let buf;
    try { buf = await readBodyBuf(req, UPLOAD_MAX_MB * 1024 * 1024); } catch (e) { return json(res, 413, { ok: false, error: '文件过大（上限 ' + UPLOAD_MAX_MB + ' MB）' }); }
    let saved = { ok: false, status: 500, detail: '上传失败' };
    try {
      execFileSync('sudo', ['-n', UPLOAD_HELPER, home, dirAbs, name], { input: buf, maxBuffer: 1024 * 1024, timeout: 120000, stdio: ['pipe', 'ignore', 'pipe'] });
      saved = { ok: true, status: 200, detail: '' };
    } catch (e) {
      const code = (e && typeof e.status === 'number') ? e.status : 0;
      if (code === 2) saved = { ok: false, status: 400, detail: '文件名不合法' };
      else if (code === 3) saved = { ok: false, status: 403, detail: '目标目录超出你的工作区' };
      else if (code === 4) saved = { ok: false, status: 404, detail: '目标目录不存在' };
      else if (code === 5) saved = { ok: false, status: 413, detail: '文件过大' };
      else saved = { ok: false, status: 500, detail: '写入失败：' + ((e && e.message) ? String(e.message).split('\n')[0] : '未知错误') };
    }
    if (!saved.ok) return json(res, saved.status, { ok: false, error: saved.detail });
    const target = path.join(dirAbs, name);
    logLine(req, 200, 'upload ' + path.relative(home, target));
    return json(res, 200, { ok: true, path: target, name: name });
  }

  if (pathname === '/__gw/download' || pathname === '/__gw/files') {
    if (req.method !== 'GET') return json(res, 405, { ok: false, error: '方法不允许' });
    if (!session) return redirect(res, '/login');
    if (!hasKey(session.u)) return redirect(res, '/setup');
    const home = userHome(session.u);
    if (!home) {
      clearSession(res);
      return json(res, 401, { ok: false, error: '账号不可用' });
    }
    let q = {};
    try { q = Object.fromEntries(new URL(req.url, 'http://gw').searchParams.entries()); } catch (e) {}
    const rawPath = String(q.path || '');

    if (pathname === '/__gw/download') {
      if (!rawPath || rawPath.length > 4096 || rawPath.indexOf('\0') >= 0) return json(res, 400, { ok: false, error: '缺少或非法的 path 参数' });
      const abs = path.resolve(rawPath);
      const base = path.basename(abs);
      if (base.startsWith('.')) return json(res, 403, { ok: false, error: '不允许下载隐藏文件' });
      // All file access runs through the pinned root helpers: the gateway's
      // service account has no read access to user homes by design.
      let size = -1;
      try {
        const out = execFileSync('sudo', ['-n', FILE_STAT_HELPER, home, abs], { timeout: 15000, maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }).toString('utf8').trim();
        size = parseInt(out, 10);
        if (!Number.isFinite(size)) size = -1;
      } catch (e) {
        const code = (e && typeof e.status === 'number') ? e.status : 0;
        if (code === 3) return json(res, 403, { ok: false, error: '路径超出你的工作区' });
        if (code === 5) return json(res, 403, { ok: false, error: '不允许下载隐藏文件' });
        return json(res, 404, { ok: false, error: '文件不存在' });
      }
      const ascii = base.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_') || 'download';
      secHeaders(res);
      const head = {
        'Content-Type': dlContentType(base),
        'Content-Disposition': 'attachment; filename="' + ascii + '"; filename*=UTF-8\'\'' + encodeURIComponent(base),
        'Cache-Control': 'no-store',
      };
      if (size >= 0) head['Content-Length'] = String(size);
      const child = spawn('sudo', ['-n', FILE_READ_HELPER, home, abs], { stdio: ['ignore', 'pipe', 'ignore'] });
      let started = false;
      child.stdout.on('data', (c) => {
        if (!started) { res.writeHead(200, head); started = true; }
        res.write(c);
      });
      child.on('error', () => { try { res.destroy(); } catch (e) {} });
      child.on('exit', (code) => {
        if (!started) {
          if (code === 3) return json(res, 403, { ok: false, error: '路径超出你的工作区' });
          if (code === 5) return json(res, 403, { ok: false, error: '不允许下载隐藏文件' });
          return json(res, 404, { ok: false, error: '文件不存在' });
        }
        res.end();
        logLine(req, 200, 'download ' + path.relative(home, abs));
      });
      req.on('error', () => { try { child.kill(); } catch (e) {} });
      res.on('close', () => { try { child.kill(); } catch (e) {} });
      return;
    }

    // /__gw/files -- directory browser (listing runs in the pinned root helper:
    // the gateway's service account has no read access to user homes by design).
    // Default target: the user's current conversation cwd (tracked from the
    // SPA's session RPCs), else the workspace directory.
    const dirParam = String(q.dir || '') || currentCwd(session.u) || '';
    let listing = null;
    try {
      const out = execFileSync('sudo', ['-n', FILE_LIST_HELPER, home, dirParam], { timeout: 15000, maxBuffer: 8 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }).toString('utf8');
      listing = JSON.parse(out);
    } catch (e) {
      const code = (e && typeof e.status === 'number') ? e.status : 0;
      if (code === 3 && !q.dir) {
        try {
          const out2 = execFileSync('sudo', ['-n', FILE_LIST_HELPER, home, ''], { timeout: 15000, maxBuffer: 8 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }).toString('utf8');
          listing = JSON.parse(out2);
        } catch (e2) {
          return json(res, 404, { ok: false, error: '目录不存在或无法读取' });
        }
      } else {
        return json(res, code === 3 ? 403 : 404, { ok: false, error: code === 3 ? '路径超出你的工作区' : '目录不存在或无法读取' });
      }
    }
    const dir = listing.dir;
    const root = listing.home || home;
    const crumbs = [];
    {
      const rel = path.relative(root, dir);
      const parts = rel ? rel.split(path.sep) : [];
      let acc = root;
      crumbs.push('<a href="/__gw/files?dir=' + encodeURIComponent(root) + '">&#127968; 根目录</a>');
      for (const part of parts) {
        acc = path.join(acc, part);
        crumbs.push('<span class="sep">/</span><a href="/__gw/files?dir=' + encodeURIComponent(acc) + '">' + esc(part) + '</a>');
      }
    }
    const rows = [];
    for (const e of listing.entries) {
      const p = path.join(dir, e.name);
      if (e.dir) {
        rows.push('<a class="row" href="/__gw/files?dir=' + encodeURIComponent(p) + '"><span class="ic">&#128193;</span><span class="nm">' + esc(e.name) + '/</span><span class="sz"></span></a>');
      } else {
        rows.push('<div class="row"><span class="ic">&#128196;</span><span class="nm">' + esc(e.name) + '</span><span class="sz">' + (e.size >= 0 ? fmtSize(e.size) : '') + '</span><a class="dl" href="/__gw/download?path=' + encodeURIComponent(p) + '">下载</a></div>');
      }
    }
    const truncated = listing.truncated === true;
    const embed = String(q.embed || '') === '1';
    const body = [
      '<div class="dlcard' + (embed ? ' embed' : '') + '">',
      '<div class="dlhead"><div><h1>&#128193; 交付文件</h1><p class="sub">任务产出的文件保存在你的工作区里：点击「下载」保存到本地，也可以从本机上传文件到当前目录。</p></div>',
      '<a class="ghost" href="/" id="backbtn">返回应用</a>',
      '</div>',
      '<div class="crumbs">' + crumbs.join('') + '</div>',
      '<div class="upbar"><input type="file" id="upfile" multiple><button type="button" id="upbtn">上传到当前目录</button></div>',
      '<div class="upmsg" id="upmsg"></div>',
      '<div class="list">' + (rows.length ? rows.join('') : '<p class="empty">此目录为空</p>') + '</div>',
      truncated ? '<p class="hint">目录内容过多，仅显示前 2000 项。</p>' : '',
      '<script>',
      'function backToApp(){if(window.parent!==window){try{parent.postMessage("dshgw-close","*");}catch(e){location.href="/";}}else{location.href="/";}}document.getElementById("backbtn").addEventListener("click",function(e){e.preventDefault();backToApp();});',
      '(function(){var dir=' + JSON.stringify(dir).replace(/</g, '\\u003c') + ';var f=document.getElementById("upfile");var b=document.getElementById("upbtn");var m=document.getElementById("upmsg");',
      'b.addEventListener("click",function(){if(!f.files||f.files.length===0){m.textContent="请先选择文件";return;}var files=Array.prototype.slice.call(f.files);var i=0;',
      'function next(){if(i>=files.length){m.textContent="上传完成，正在刷新…";location.reload();return;}var file=files[i];m.textContent="上传中 "+(i+1)+"/"+files.length+"："+file.name;',
      'fetch("/__gw/upload?dir="+encodeURIComponent(dir)+"&name="+encodeURIComponent(file.name),{method:"POST",body:file}).then(function(r){return r.json().catch(function(){return {};}).then(function(j){if(!r.ok)throw new Error(j.error||("HTTP "+r.status));});}).then(function(){i++;next();}).catch(function(e){m.textContent="上传失败："+(e&&e.message?e.message:e)+"（第 "+(i+1)+" 个："+file.name+"）";});}',
      'next();});})();',
      '</scr' + 'ipt>',
      '<style>',
      'body{background:#f6f8fa}',
      '.dlcard{width:100%;max-width:780px;background:#fcfcfd;border:1px solid #e2e8f0;border-radius:14px;padding:24px 26px;box-shadow:0 1px 2px rgba(16,24,40,.05),0 12px 32px rgba(16,24,40,.10)}',
      '.dlcard.embed{max-width:none;width:100%;border:0;border-radius:0;box-shadow:none;padding:18px 22px 24px;min-height:100%;box-sizing:border-box}',
      '.dlhead{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:14px}',
      '.dlcard.embed .dlhead{padding-right:44px}',
      '.dlhead h1{font-size:17px;font-weight:650;margin:0;color:#0f172a;letter-spacing:.2px}',
      '.dlhead .sub{font-size:13px;color:#64748b;margin:6px 0 0;max-width:560px;line-height:1.55}',
      '.ghost{white-space:nowrap;color:#2563eb;text-decoration:none;font-size:13px;padding:8px 14px;border:1px solid #e2e8f0;border-radius:10px;background:#fff;cursor:pointer;margin-top:0;width:auto}',
      '.ghost:hover{background:#f1f5f9}',
      '.crumbs{font-size:12.5px;color:#64748b;padding:9px 12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;margin-bottom:12px;overflow-x:auto;white-space:nowrap}',
      '.crumbs a{color:#2563eb;text-decoration:none}.crumbs a:hover{text-decoration:underline}',
      '.crumbs .sep{margin:0 6px;color:#cbd5e1}',
      '.list{border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;max-height:52vh;overflow-y:auto;background:#fff}',
      '.row{display:flex;align-items:center;gap:10px;padding:10px 14px;font-size:14px;border-bottom:1px solid #f1f5f9;color:#1e293b;text-decoration:none}',
      '.row:last-child{border-bottom:0}.row:hover{background:#f8fafc}',
      '.ic{width:20px;text-align:center}.nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
      '.sz{color:#94a3b8;font-size:12px;white-space:nowrap;font-variant-numeric:tabular-nums}',
      '.dl{color:#2563eb;text-decoration:none;font-size:12.5px;font-weight:600;white-space:nowrap;padding:5px 12px;border:1px solid #dbeafe;border-radius:8px;background:#eff6ff}',
      '.dl:hover{background:#dbeafe}',
      '.empty{color:#64748b;font-size:13px;padding:20px 14px;margin:0}',
      '.upbar{display:flex;gap:10px;align-items:center;margin-bottom:10px}',
      '.upbar input[type=file]{flex:1;width:auto;background:#f8fafc;border:1px dashed #cbd5e1;border-radius:10px;color:#64748b;font-size:12.5px;padding:9px 12px}',
      '.upbar input[type=file]:focus-visible{outline:2px solid #2563eb;outline-offset:2px}',
      '.upbar button{margin-top:0;width:auto;padding:9px 18px;font-size:13px;font-weight:600;background:#2563eb;color:#fff;border-radius:10px}',
      '.upbar button:hover{filter:none;background:#1d4ed8}',
      '.upbar button:focus-visible{outline:2px solid #2563eb;outline-offset:2px}',
      '.upmsg{font-size:12.5px;color:#64748b;margin:0 0 10px;min-height:16px}',
      '.hint{font-size:12.5px;color:#64748b;margin-top:10px}',
      (embed ? 'body{background:#fcfcfd;padding:0;align-items:stretch}' : ''),
      '</style>',
      '</div>',
    ].join('');
    secHeaders(res);
    // The in-page drawer embeds this page in a same-origin iframe inside the SPA.
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(htmlShell('交付文件', body));
  }

  // everything else
  if (!session) {
    if (req.method === 'GET' && !pathname.startsWith('/api/')) {
      const csrf = crypto.randomBytes(16).toString('hex');
      res.setHeader('Set-Cookie', cookieHeader(CSRF_COOKIE, csrf, { maxAge: 600, path: '/', sameSite: 'Lax' }));
      secHeaders(res);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(loginPage(csrf, null));
    }
    return json(res, 401, { ok: false, error: '未登录' });
  }
  if (!hasKey(session.u)) {
    if (req.method === 'GET' && !pathname.startsWith('/api/')) return redirect(res, '/setup');
    return json(res, 403, { ok: false, error: '请先配置 API Key', redirect: '/setup' });
  }
  const u = getUser(session.u);
  if (!u || !u.port) {
    clearSession(res);
    return json(res, 401, { ok: false, error: '账号不可用' });
  }
  proxyRequest(req, res, u.port, session.u);
});

server.on('upgrade', (req, socket, head) => {
  const session = getSession(req);
  if (!session) { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); socket.destroy(); return; }
  if (!hasKey(session.u)) { socket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); socket.destroy(); return; }
  const u = getUser(session.u);
  if (!u || !u.port) { socket.destroy(); return; }
  proxyUpgrade(req, socket, head, u.port);
});

server.listen(PORT, HOST, () => {
  console.log('dsh-gateway listening on ' + HOST + ':' + PORT);
});
