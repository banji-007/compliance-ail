// M2 attempt A3: inspect the process tree and environment (of the agent's own
// container) for the upstream server's address or credentials. A compromised
// agent would grep every process's cmdline and environ under /proc.

import fs from 'node:fs';

console.log('--- A3: process tree + environment inspection ---');

console.log('A3 own-env keys:', Object.keys(process.env).sort().join(', '));
for (const k of ['AIL_UPSTREAM_URL', 'AIL_UPSTREAM_SECRET', 'UPSTREAM_API_KEY', 'AIL_UPSTREAM_ARGS']) {
  console.log(`A3 own-env ${k} = ${process.env[k] ?? '<unset>'}`);
}

let procDirs = [];
try {
  procDirs = fs.readdirSync('/proc').filter(d => /^\d+$/.test(d));
} catch (e) {
  console.log(`A3 RESULT: /proc unavailable (${e.code}); cannot inspect other processes from this container`);
}

let foundSecret = false, foundUpstreamAddr = false, sawForeign = false;
for (const pid of procDirs) {
  let cmdline = '', environ = '';
  try { cmdline = fs.readFileSync(`/proc/${pid}/cmdline`).toString().replace(/\0/g, ' ').trim(); } catch {}
  try { environ = fs.readFileSync(`/proc/${pid}/environ`).toString().replace(/\0/g, '\n'); } catch (e) {
    if (pid !== String(process.pid) && e.code === 'EACCES') sawForeign = 'EACCES';
  }
  const isOurs = pid === String(process.pid);
  if (!isOurs && cmdline) {
    console.log(`A3 visible pid ${pid}: ${cmdline.slice(0, 100)}`);
  }
  if (/proxy-|server-everything|upstream:3001|:3001\/mcp/.test(cmdline)) foundUpstreamAddr = true;
  if (/s3cr3t|UPSTREAM_API_KEY=|AIL_UPSTREAM_SECRET=/.test(environ) && !isOurs) foundSecret = true;
}

console.log(`A3 RESULT: other processes visible in /proc: ${procDirs.filter(p => p !== String(process.pid)).length}`);
console.log(`A3 RESULT: found upstream address in any foreign cmdline: ${foundUpstreamAddr ? 'YES' : 'NO'}`);
console.log(`A3 RESULT: found upstream secret in any foreign environ:  ${foundSecret ? 'YES' : 'NO'}`);
if (sawForeign === 'EACCES') console.log('A3 NOTE: foreign /proc/<pid>/environ returned EACCES (kernel-enforced)');
