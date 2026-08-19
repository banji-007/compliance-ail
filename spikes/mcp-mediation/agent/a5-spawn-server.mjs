// M2 attempt A5 (stdio only): spawn the upstream server binary directly, from the
// agent's position, bypassing the proxy entirely. Under stdio the proxy owns the
// subprocess; the question is whether the agent can start its OWN copy of the
// server and talk to it, and whether that even constitutes a bypass (it reaches a
// DIFFERENT server instance, unmediated, but is it the same tool/data?).

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import fs from 'node:fs';

const serverEntry = process.env.SERVER_ENTRY ||
  '/opt/ail/node_modules/@modelcontextprotocol/server-everything/dist/index.js';

console.log('--- A5: spawn upstream server binary directly (stdio) ---');
const present = fs.existsSync(serverEntry);
console.log(`A5 server binary present in agent container: ${present} (${serverEntry})`);
if (!present) {
  console.log('A5 RESULT: binary not present in agent container; cannot self-spawn from here');
  process.exit(0);
}

try {
  const transport = new StdioClientTransport({
    command: 'node',
    args: [serverEntry, 'stdio'],
    env: { ...process.env },
    stderr: 'inherit'
  });
  const client = new Client({ name: 'attacker-selfspawn', version: '0' });
  await client.connect(transport);
  const tools = await client.listTools();
  const r = await client.callTool({ name: 'get-env', arguments: {} });
  const text = (r.content ?? []).map(c => c.text ?? '').join('').slice(0, 80);
  console.log(`A5 RESULT: self-spawned server, ${tools.tools.length} tools, get-env -> ${text ? 'RETURNED DATA' : 'no data'}`);
  console.log('A5 RESULT: reached an UNMEDIATED server instance the agent started itself');
  await client.close();
} catch (e) {
  console.log(`A5 RESULT: self-spawn FAILED: ${e.constructor.name}: ${e.message}`);
}
