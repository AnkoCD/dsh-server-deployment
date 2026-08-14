'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');
const { hashPassword } = require('./auth.js');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'dshgw-'));
const USERS_DIR = path.join(TMP, 'users');
const USERS_FILE = path.join(TMP, 'users.json');
fs.mkdirSync(path.join(USERS_DIR, 'tester'), { recursive: true });
fs.mkdirSync(path.join(USERS_DIR, 'nokey'), { recursive: true });

const users = {
  version: 1,
  users: {
    tester: { port: 3999, home: path.join(USERS_DIR, 'tester'), osUser: 'ubuntu', pwd: hashPassword('secret123'), keyConfigured: true },
    nokey: { port: 3999, home: path.join(USERS_DIR, 'nokey'), osUser: 'ubuntu', pwd: hashPassword('secret123'), keyConfigured: false },
  },
};
fs.writeFileSync(USERS_FILE, JSON.stringify(users));

process.env.HOST = '127.0.0.1';
process.env.PORT = '3998';
process.env.USERS_FILE = USERS_FILE;
process.env.SECRET_FILE = path.join(TMP, 'secret');
process.env.USERS_DIR = USERS_DIR;
process.env.COOKIE_SECURE = '0';
process.env.DEEPSEEK_BASE_URL = 'http://127.0.0.1:3999';

const upstream = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/api/credentials.set') {
    let body = '';
    req.on('data', (c) => body += c);
    req.on('end', () => {
      let rpcId = 'x';
      try { rpcId = JSON.parse(body).rpcId || 'x'; } catch (e) {}
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ type: 'server-response', rpcId: rpcId, result: { ok: true, value: {} } }));
    });
    return;
  }
  if (req.url === '/models') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{"ok":true}'); return; }
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('UPSTREAM-OK ' + req.url);
});
upstream.listen(3999, '127.0.0.1');

require('./server.js');

function req(method, pathname, opts) {
  return new Promise((resolve, reject) => {
    opts = opts || {};
    const headers = Object.assign({}, opts.headers || {});
    const body = opts.body;
    if (body && !headers['Content-Type']) headers['Content-Type'] = 'application/x-www-form-urlencoded';
    if (body) headers['Content-Length'] = Buffer.byteLength(body);
    const r = http.request({ host: '127.0.0.1', port: 3998, method: method, path: pathname, headers: headers }, (res) => {
      let data = '';
      res.on('data', (c) => data += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}
function cookies(setCookie) {
  const out = {};
  if (!setCookie) return out;
  const arr = Array.isArray(setCookie) ? setCookie : [setCookie];
  for (const c of arr) {
    const kv = c.split(';')[0].trim();
    const i = kv.indexOf('=');
    if (i > 0) out[kv.slice(0, i)] = kv.slice(i + 1);
  }
  return out;
}

let pass = 0, fail = 0;
function check(name, cond) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; console.log('FAIL ' + name); }
}

(async () => {
  await new Promise((r) => setTimeout(r, 500));
  let r;

  r = await req('GET', '/__gw/health');
  check('health 200', r.status === 200 && r.body.indexOf('"ok":true') >= 0);

  r = await req('GET', '/login');
  check('login page brand', r.status === 200 && r.body.indexOf('DeepSeek Harness') >= 0);
  const csrf = cookies(r.headers['set-cookie'])['dsh_csrf'];

  r = await req('POST', '/login', { headers: { 'Cookie': 'dsh_csrf=' + csrf }, body: 'csrf=' + csrf + '&username=tester&password=WRONG' });
  check('wrong pw -> 401', r.status === 401);

  const csrf2 = cookies((await req('GET', '/login')).headers['set-cookie'])['dsh_csrf'];
  r = await req('POST', '/login', { headers: { 'Cookie': 'dsh_csrf=' + csrf2 }, body: 'csrf=' + csrf2 + '&username=tester&password=secret123' });
  check('tester(key) login -> 302 /', r.status === 302 && r.headers.location === '/');
  const sess = cookies(r.headers['set-cookie'])['dsh_session'];

  r = await req('GET', '/some/path', { headers: { 'Cookie': 'dsh_session=' + sess } });
  check('proxy upstream', r.status === 200 && r.body.indexOf('UPSTREAM-OK /some/path') >= 0);

  const csrf3 = cookies((await req('GET', '/login')).headers['set-cookie'])['dsh_csrf'];
  r = await req('POST', '/login', { headers: { 'Cookie': 'dsh_csrf=' + csrf3 }, body: 'csrf=' + csrf3 + '&username=nokey&password=secret123' });
  check('nokey login -> /setup', r.status === 302 && r.headers.location === '/setup');
  const sess2 = cookies(r.headers['set-cookie'])['dsh_session'];

  r = await req('GET', '/setup', { headers: { 'Cookie': 'dsh_session=' + sess2 } });
  check('setup page renders', r.status === 200 && r.body.indexOf('API Key') >= 0);

  const b64 = sess2.split('.')[0];
  const payload = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
  r = await req('POST', '/setup', { headers: { 'Cookie': 'dsh_session=' + sess2 }, body: 'csrf=' + payload.n + '&key=sk-abcdefgh123456' });
  check('setup via RPC -> 302 /', r.status === 302 && r.headers.location === '/');

  const db = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  check('flag set after setup', db.users.nokey.keyConfigured === true);

  r = await req('GET', '/api/something');
  check('unauth api -> 401', r.status === 401);

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  upstream.close();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('TEST ERROR', e); process.exit(1); });
