// The cooperating agent. A real MCP client from the official SDK, pointed at
// whatever its own config file names. Used both for the happy path (M1, M3) and,
// with a rewritten config, as one of the bypass attempts (M2).
//
// usage: node client.mjs <serverKeyFromConfig> [configPath]

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const key = process.argv[2] || 'everything';
const configPath = process.argv[3] || fileURLToPath(new URL('./mcp-config.json', import.meta.url));
const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const entry = cfg.mcpServers[key];
if (!entry) {
  console.error(`no such server key '${key}' in ${configPath}`);
  process.exit(2);
}

console.log(`[client] config file:      ${configPath}`);
console.log(`[client] server entry:     ${JSON.stringify(entry)}`);

let transport;
if (entry.transport === 'stdio') {
  // NOTE: StdioClientTransport otherwise passes only a filtered "safe" environment
  // to the child, so the proxy's own config vars have to be passed explicitly.
  transport = new StdioClientTransport({
    command: entry.command,
    args: entry.args,
    env: { ...process.env, ...(entry.env ?? {}) },
    stderr: 'inherit'
  });
} else {
  const headers = entry.headers ?? {};
  transport = new StreamableHTTPClientTransport(new URL(entry.url), { requestInit: { headers } });
}

const client = new Client({ name: 'ail-spike-agent', version: '0.0.1' });
await client.connect(transport);

const info = client.getServerVersion();
console.log(`[client] connected to:     ${JSON.stringify(info)}`);
if (transport.sessionId) console.log(`[client] mcp session id:   ${transport.sessionId}`);

const tools = await client.listTools();
console.log(`[client] tools visible:    ${tools.tools.length} -> ${tools.tools.map(t => t.name).slice(0, 8).join(', ')}...`);

async function call(name, args) {
  try {
    const r = await client.callTool({ name, arguments: args });
    const text = (r.content ?? []).map(c => c.text ?? `<${c.type}>`).join(' | ').slice(0, 220);
    console.log(`[client] call ${name} -> isError=${r.isError ?? false} :: ${text}`);
    return r;
  } catch (e) {
    console.log(`[client] call ${name} -> THREW ${e.constructor.name}: ${e.message}`);
    return null;
  }
}

await call('echo', { message: 'hello from cooperating agent' });
await call('echo', { message: 'payload AIL-FORBIDDEN smuggled' });
await call('get-env', {});

await client.close();
process.exit(0);
