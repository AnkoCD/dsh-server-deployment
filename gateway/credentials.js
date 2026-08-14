'use strict';
const fs = require('fs');
const path = require('path');

function credentialsPath(usersDir, user) {
  return path.join(usersDir, user, '.credentials.yaml');
}

function hasApiKey(usersDir, user) {
  try {
    const raw = fs.readFileSync(credentialsPath(usersDir, user), 'utf8');
    const m = raw.match(/^\s*DEEPSEEK_API_KEY\s*:\s*(.+?)\s*$/m);
    if (!m) return false;
    let v = m[1].trim();
    if ((v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') ||
        (v.charAt(0) === "'" && v.charAt(v.length - 1) === "'")) v = v.slice(1, -1);
    return v.length > 0;
  } catch (e) { return false; }
}

function setApiKey(usersDir, user, key) {
  const file = credentialsPath(usersDir, user);
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  let lines = [];
  try { lines = fs.readFileSync(file, 'utf8').split(/\r?\n/); } catch (e) {}
  const esc = String(key).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const newLine = 'DEEPSEEK_API_KEY: "' + esc + '"';
  let replaced = false;
  const out = [];
  for (const line of lines) {
    if (/^\s*DEEPSEEK_API_KEY\s*:/.test(line)) { out.push(newLine); replaced = true; }
    else out.push(line);
  }
  if (!replaced) {
    while (out.length && out[out.length - 1].trim() === '') out.pop();
    out.push(newLine);
  }
  fs.writeFileSync(file, out.join('\n') + '\n', { mode: 0o600 });
  try { fs.chmodSync(file, 0o600); fs.chmodSync(dir, 0o700); } catch (e) {}
}

module.exports = { credentialsPath, hasApiKey, setApiKey };
