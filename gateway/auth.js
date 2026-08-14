'use strict';
const crypto = require('crypto');
const { spawnSync } = require('child_process');

function timingSafeStr(a, b) {
  const ba = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// scrypt password record: { algo: 'scrypt', value: '<saltHex>$<hashHex>' }
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return { algo: 'scrypt', value: salt.toString('hex') + '$' + hash.toString('hex') };
}

// legacy APR1 (Apache htpasswd) verification via the system openssl tool
function verifyApr1(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length < 4 || parts[1] !== 'apr1') return false;
  const salt = parts[2];
  let computed = '';
  try {
    const r = spawnSync('openssl', ['passwd', '-apr1', '-salt', salt], {
      input: password + '\n', encoding: 'utf8', timeout: 5000,
    });
    computed = (r.stdout || '').trim();
  } catch (e) { return false; }
  return computed.length > 0 && timingSafeStr(computed, stored);
}

function verifyPassword(password, record) {
  if (!record || typeof record !== 'object') return false;
  if (record.algo === 'apr1') return verifyApr1(password, record.value);
  if (record.algo === 'scrypt') {
    const s = String(record.value || '');
    const idx = s.indexOf('$');
    if (idx < 0) return false;
    let salt, expected;
    try {
      salt = Buffer.from(s.slice(0, idx), 'hex');
      expected = Buffer.from(s.slice(idx + 1), 'hex');
    } catch (e) { return false; }
    const actual = crypto.scryptSync(password, salt, expected.length);
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  }
  return false;
}

module.exports = { timingSafeStr, hashPassword, verifyPassword, verifyApr1 };
