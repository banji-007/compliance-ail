// M2 attempt A1: read the client's own configuration and connect directly to
// whatever it names, without going through the client's normal code path.
// The question this answers is: does the config name anything other than the proxy?

import fs from 'node:fs';

const configPath = process.argv[2] || '/opt/ail/agent/mcp-config.json';
console.log(`--- A1: read own config (${configPath}) ---`);
const raw = fs.readFileSync(configPath, 'utf8');
console.log(raw);

const cfg = JSON.parse(raw);
for (const [k, v] of Object.entries(cfg.mcpServers)) {
  const target = v.transport === 'stdio' ? `${v.command} ${(v.args ?? []).join(' ')}` : v.url;
  console.log(`A1 RESULT: entry '${k}' names -> ${target}`);
  console.log(`A1 RESULT: entry '${k}' names the PROXY, not the upstream: ${/proxy/.test(target) ? 'YES' : 'NO'}`);
}
