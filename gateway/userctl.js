'use strict';
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { hashPassword } = require('./auth.js');
const { hasApiKey, setApiKey } = require('./credentials.js');

const BASE_DIR = '/opt/deepseek-harness';
const USERS_DIR = process.env.DSH_USERS_DIR || path.join(BASE_DIR, 'users');
const USERS_FILE = process.env.DSH_USERS_FILE || path.join(BASE_DIR, 'gateway', 'users.json');
const SETTINGS_SRC = path.join(BASE_DIR, 'settings.yaml');
const NODE_BIN = path.join(BASE_DIR, 'runtime', 'bin', 'node');
const DSH_BIN = path.join(BASE_DIR, 'app', 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js');
const TRUSTED_HOST = process.env.DSH_TRUSTED_HOST || '127.0.0.1:1145';
const BASE_URL = process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com';
const MIN_PORT = 3101;

function fail(msg) { console.error('error: ' + msg); process.exit(1); }
function validUser(n) { return typeof n === 'string' && /^[A-Za-z0-9_-]+$/.test(n); }

// OS account per DSH user: 'dsh-' + lowercase(username). Each user's DSH
// instance runs as its own OS account so one user cannot read another's files.
function osUserOf(name) { return 'dsh-' + String(name).toLowerCase(); }
function osUserExists(name) {
  try { execFileSync('id', [name], { stdio: 'ignore' }); return true; } catch (e) { return false; }
}
function createOsUser(name) {
  const osu = osUserOf(name);
  if (osUserExists(osu)) return;
  execFileSync('useradd', ['--system', '--no-create-home', '--home', homeOf(name), '--shell', '/usr/sbin/nologin', osu]);
}
function removeOsUser(name) {
  const osu = osUserOf(name);
  if (!osUserExists(osu)) return;
  try { execFileSync('userdel', [osu]); } catch (e) {}
}

function loadUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch (e) { return { version: 1, users: {} }; }
}
function saveUsers(db) {
  fs.mkdirSync(path.dirname(USERS_FILE), { recursive: true, mode: 0o700 });
  fs.writeFileSync(USERS_FILE, JSON.stringify(db, null, 2) + '\n', { mode: 0o640 });
  try { execFileSync('chown', ['ubuntu:ubuntu', USERS_FILE]); } catch (e) {}
}
function allocPort(db) {
  const used = new Set();
  for (const k in (db.users || {})) used.add(db.users[k].port);
  let p = MIN_PORT;
  while (used.has(p)) p++;
  return p;
}
function homeOf(name) { return path.join(USERS_DIR, name); }

// Enable full-text session search for this user. DSH ships the
// session-query-sqlite index with openAt: never (content search is opt-in),
// which makes the web client degrade to name-only matching. The home-level
// patch layer applies over every profile, so this one file enables content
// search for web and headless profiles alike; the in-memory SQLite index
// opens on first search.
const SEARCH_PATCH = [
  '# $DSH_HOME patch layer - applied over every profile own layer.',
  '# Enables full-text session search (opt-in in DSH): the session-query-sqlite',
  '# index defaults to openAt: never; open the in-memory SQLite index on first',
  '# search instead.',
  '- id: session-query-sqlite',
  '  config:',
  "    path: ':memory:'",
  '    openAt: first-search',
  '',
].join('\n');
function writeSearchPatch(name) {
  const file = path.join(homeOf(name), 'cordis.patch.yml');
  if (fs.existsSync(file)) return;
  fs.writeFileSync(file, SEARCH_PATCH, { mode: 0o644 });
}

function createHome(name) {
  const home = homeOf(name);
  fs.mkdirSync(path.join(home, 'workspace'), { recursive: true, mode: 0o700 });
  const settings = path.join(home, 'settings.yaml');
  if (!fs.existsSync(settings)) {
    if (fs.existsSync(SETTINGS_SRC)) fs.copyFileSync(SETTINGS_SRC, settings);
    else {
      const def = ['agent-default-model:', '  provider: deepseek-official', '  model: deepseek-v4-flash', '  reasoningEffort: max', ''].join('\n');
      fs.writeFileSync(settings, def);
    }
  }
  writeSearchPatch(name);
  const osu = osUserOf(name);
  execFileSync('chown', ['-R', osu + ':' + osu, home]);
  try { fs.chmodSync(home, 0o700); } catch (e) {}
  stripGatewayAcl(home);
}

// File access for the web gateway now runs through pinned root helpers
// (dsh-file-list/stat/read/put), so user homes must NOT carry a gateway-read
// ACL. Older userctl versions granted one (named + default), which also broke
// DSH's owner-only credentials boot check (the ACL mask showed up in stat
// mode). Strip any extended ACL so .credentials.yaml stays a plain 0600 file.
function stripGatewayAcl(home) {
  try { execFileSync('setfacl', ['-b', '-R', home]); } catch (e) {}
}

function unitFor(name, port) {
  const home = homeOf(name);
  const osu = osUserOf(name);
  return [
    '[Unit]',
    'Description=DeepSeek Harness Web - user ' + name,
    'After=network-online.target',
    'Wants=network-online.target',
    '',
    '[Service]',
    'Type=simple',
    'User=' + osu,
    'Group=' + osu,
    'WorkingDirectory=' + path.join(home, 'workspace'),
    'Environment=DSH_HOME=' + home,
    'Environment=HOME=' + home,
    'Environment=PATH=' + path.join(BASE_DIR, 'runtime', 'bin') + ':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'Environment=DEEPSEEK_BASE_URL=' + BASE_URL,
    'ExecStart=' + NODE_BIN + ' ' + DSH_BIN + ' --profile web --host 127.0.0.1 --port ' + port + ' --trusted-host ' + TRUSTED_HOST,
    'Restart=on-failure',
    'RestartSec=5',
    '',
    '[Install]',
    'WantedBy=multi-user.target',
    '',
  ].join('\n');
}
function writeUnit(name, port) {
  const file = '/etc/systemd/system/dsh-web-' + name + '.service';
  fs.writeFileSync(file, unitFor(name, port), { mode: 0o644 });
  execFileSync('systemctl', ['daemon-reload']);
  execFileSync('systemctl', ['enable', '--now', 'dsh-web-' + name + '.service']);
}
function removeUnit(name) {
  const unit = 'dsh-web-' + name + '.service';
  try { execFileSync('systemctl', ['disable', '--now', unit]); } catch (e) {}
  try { fs.unlinkSync('/etc/systemd/system/' + unit); } catch (e) {}
  try { execFileSync('systemctl', ['daemon-reload']); } catch (e) {}
}

function promptHidden(promptText) {
  return new Promise((resolve) => {
    process.stderr.write(promptText);
    const stdin = process.stdin;
    if (stdin.isTTY) stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    const onData = (ch) => {
      const c = ch.charCodeAt(0);
      if (c === 3) { process.exit(130); }
      else if (c === 13 || c === 10) {
        if (stdin.isTTY) stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stderr.write(String.fromCharCode(10));
        resolve(buf);
      } else if (c === 127 || c === 8) {
        buf = buf.slice(0, -1);
      } else {
        buf += ch;
      }
    };
    stdin.on('data', onData);
  });
}
function promptLine(promptText) {
  return new Promise((resolve) => {
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
    rl.question(promptText, (ans) => { rl.close(); resolve(ans.trim()); });
  });
}

function usage() {
  console.log('Usage:');
  console.log('  dsh-users.sh add <user> [password]');
  console.log('  dsh-users.sh passwd <user> [password]');
  console.log('  dsh-users.sh del <user> [--yes]');
  console.log('  dsh-users.sh list');
  console.log('  dsh-users.sh set-key <user> [key]');
  console.log('  dsh-users.sh key-status [user]');
  console.log('  dsh-users.sh rehome <user>   # (internal) move user to their OS account');
  process.exit(1);
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const user = argv[1];
  const rest = argv.slice(2);

  if (!cmd) usage();

  if (cmd === 'list') {
    const db = loadUsers();
    const names = Object.keys(db.users || {}).sort();
    if (names.length === 0) { console.log('(no users)'); return; }
    console.log('USER\tPORT\tOS_USER\tALGO\tAPI_KEY');
    for (const n of names) {
      const u = db.users[n];
      console.log(n + '\t' + (u.port || '-') + '\t' + (u.osUser || '-') + '\t' + ((u.pwd && u.pwd.algo) || '-') + '\t' + (u.keyConfigured ? 'configured' : 'MISSING'));
    }
    return;
  }

  if (!user || !validUser(user)) fail('invalid username (letters, digits, underscore, hyphen only)');

  const db = loadUsers();

  if (cmd === 'add') {
    if (db.users[user]) fail('user already exists: ' + user);
    const password = rest[0] || await promptHidden('Password: ');
    if (!password) fail('password required');
    const port = allocPort(db);
    const osu = osUserOf(user);
    createOsUser(user);
    db.users[user] = { port: port, home: homeOf(user), osUser: osu, pwd: hashPassword(password), keyConfigured: false, created: new Date().toISOString() };
    createHome(user);
    saveUsers(db);
    writeUnit(user, port);
    console.log('Created user: ' + user + ' (port ' + port + ', os ' + osu + ')');
    return;
  }

  if (cmd === 'passwd') {
    if (!db.users[user]) fail('user not found: ' + user);
    const password = rest[0] || await promptHidden('New password: ');
    if (!password) fail('password required');
    db.users[user].pwd = hashPassword(password);
    saveUsers(db);
    console.log('Password updated: ' + user + ' (now scrypt)');
    return;
  }

  if (cmd === 'del') {
    if (!db.users[user]) fail('user not found: ' + user);
    const yes = rest.indexOf('--yes') >= 0;
    if (!yes) {
      const ans = await promptLine('Delete user "' + user + '" and ALL their data (sessions, files, key)? [y/N] ');
      if (ans !== 'y' && ans !== 'Y') { console.log('aborted'); return; }
    }
    removeUnit(user);
    removeOsUser(user);
    try { fs.rmSync(homeOf(user), { recursive: true, force: true }); } catch (e) {}
    delete db.users[user];
    saveUsers(db);
    console.log('Deleted user: ' + user);
    return;
  }

  if (cmd === 'set-key') {
    if (!db.users[user]) fail('user not found: ' + user);
    const key = rest[0] || await promptHidden('API Key: ');
    if (!key) fail('key required');
    setApiKey(USERS_DIR, user, key);
    const osu = db.users[user].osUser || osUserOf(user);
    try { execFileSync('chown', [osu + ':' + osu, path.join(USERS_DIR, user, '.credentials.yaml')]); } catch (e) {}
    // setApiKey chmods the home to 0700; keep the tree free of extended ACLs
    // so .credentials.yaml stays a plain 0600 owner-only file.
    stripGatewayAcl(homeOf(user));
    db.users[user].keyConfigured = true;
    saveUsers(db);
    console.log('API key saved for: ' + user);
    return;
  }

  if (cmd === 'key-status') {
    if (!db.users[user]) fail('user not found: ' + user);
    console.log(user + ': ' + (db.users[user].keyConfigured ? 'configured' : 'MISSING'));
    return;
  }

  if (cmd === 'rehome') {
    if (!db.users[user]) fail('user not found: ' + user);
    const osu = osUserOf(user);
    createOsUser(user);
    execFileSync('chown', ['-R', osu + ':' + osu, homeOf(user)]);
    try { fs.chmodSync(homeOf(user), 0o700); } catch (e) {}
    stripGatewayAcl(homeOf(user));
    db.users[user].osUser = osu;
    if (db.users[user].keyConfigured === undefined) db.users[user].keyConfigured = hasApiKey(USERS_DIR, user);
    saveUsers(db);
    const file = '/etc/systemd/system/dsh-web-' + user + '.service';
    fs.writeFileSync(file, unitFor(user, db.users[user].port), { mode: 0o644 });
    execFileSync('systemctl', ['daemon-reload']);
    execFileSync('systemctl', ['restart', 'dsh-web-' + user + '.service']);
    console.log('Rehomed user: ' + user + ' -> os ' + osu);
    return;
  }

  if (cmd === 'seed-legacy') {
    const apr1 = rest[0];
    if (db.users[user]) fail('user already exists: ' + user);
    if (!apr1 || apr1.indexOf('$apr1$') !== 0) fail('seed-legacy requires an $apr1$ hash');
    const port = allocPort(db);
    const osu = osUserOf(user);
    createOsUser(user);
    db.users[user] = { port: port, home: homeOf(user), osUser: osu, pwd: { algo: 'apr1', value: apr1 }, keyConfigured: false, created: new Date().toISOString() };
    createHome(user);
    saveUsers(db);
    writeUnit(user, port);
    console.log('Seeded legacy user: ' + user + ' (port ' + port + ', os ' + osu + ')');
    return;
  }

  usage();
}

main().catch((e) => { console.error('error: ' + (e && e.message ? e.message : e)); process.exit(1); });
