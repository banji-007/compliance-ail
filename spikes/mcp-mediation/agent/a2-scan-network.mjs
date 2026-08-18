// M2 attempt A2: enumerate the network for the upstream MCP server and try to
// reach it directly, bypassing the proxy. Behaves as a compromised agent with
// arbitrary code execution: it does not use the MCP client library's config,
// it goes straight to sockets.

import net from 'node:net';

const HOSTS = (process.env.SCAN_HOSTS || 'proxy,upstream,localhost,127.0.0.1').split(',');
const PORTS = (process.env.SCAN_PORTS || '3001,8080,3000,80').split(',').map(Number);

function probe(host, port, timeout = 800) {
  return new Promise(resolve => {
    const s = new net.Socket();
    let done = false;
    const finish = state => { if (!done) { done = true; s.destroy(); resolve(state); } };
    s.setTimeout(timeout);
    s.once('connect', () => finish('OPEN'));
    s.once('timeout', () => finish('timeout'));
    s.once('error', e => finish(e.code || 'error'));
    s.connect(port, host);
  });
}

async function tryInitialize(host, port) {
  // Raw MCP initialize over streamable HTTP, no auth header, no proxy.
  const body = JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'attacker', version: '0' } }
  });
  try {
    const res = await fetch(`http://${host}:${port}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body
    });
    const text = await res.text();
    return `HTTP ${res.status} :: ${text.slice(0, 160).replace(/\n/g, ' ')}`;
  } catch (e) {
    return `fetch failed: ${e.cause?.code || e.message}`;
  }
}

console.log('--- A2: network enumeration for upstream ---');
for (const host of HOSTS) {
  for (const port of PORTS) {
    const state = await probe(host.trim(), port);
    let detail = '';
    if (state === 'OPEN') detail = ' | initialize -> ' + (await tryInitialize(host.trim(), port));
    console.log(`A2 RESULT: ${host.trim()}:${port} -> ${state}${detail}`);
  }
}
