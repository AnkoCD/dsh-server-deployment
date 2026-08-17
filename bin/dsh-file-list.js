'use strict';
// dsh-file-list.js <home> [dir] -- print JSON {home, dir, truncated, entries:[{name,dir,size,mtime}]}.
// Runs as the home's own OS user via the dsh-file-list wrapper (issue #1);
// its realpath/prefix validation keeps exit codes stable but the OS account
// is the real boundary.
const fs = require('fs');
const path = require('path');
const home = process.argv[2] || '';
const dir = process.argv[3] || '';
function fail(code) { process.exit(code); }
if (!home || home.indexOf('\0') >= 0 || dir.indexOf('\0') >= 0) fail(2);
let hd;
try { hd = fs.realpathSync(home); } catch (e) { fail(3); }
let target;
if (dir) {
  try { target = fs.realpathSync(dir); } catch (e) { fail(4); }
} else {
  const ws = path.join(hd, 'workspace');
  try { target = fs.realpathSync(ws); } catch (e) { target = hd; }
}
if (target !== hd && !target.startsWith(hd + path.sep)) fail(3);
let st;
try { st = fs.statSync(target); } catch (e) { fail(4); }
if (!st.isDirectory()) fail(4);
let entries = [];
try {
  entries = fs.readdirSync(target, { withFileTypes: true })
    .filter((e) => !e.name.startsWith('.'))
    .map((e) => {
      const p = path.join(target, e.name);
      let size = -1, mtime = 0;
      if (!e.isDirectory()) {
        try { const s = fs.statSync(p); size = s.size; mtime = Math.floor(s.mtimeMs); } catch (err) {}
      }
      return { name: e.name, dir: e.isDirectory(), size, mtime };
    })
    .sort((a, b) => (a.dir === b.dir ? a.name.localeCompare(b.name) : a.dir ? -1 : 1));
} catch (e) { fail(4); }
const truncated = entries.length > 2000;
if (truncated) entries = entries.slice(0, 2000);
process.stdout.write(JSON.stringify({ home: hd, dir: target, truncated, entries }));
