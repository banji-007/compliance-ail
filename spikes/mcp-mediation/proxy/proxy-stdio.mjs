// stdio front end: the AGENT spawns this proxy as a subprocess and talks to it
// over the proxy's own stdin/stdout. The proxy in turn spawns the real
// off-the-shelf MCP server as ITS subprocess.
//
//   agent client  --stdio-->  proxy  --stdio-->  @modelcontextprotocol/server-everything
//
// Nothing listens on a socket anywhere in this topology.

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { buildProxyServer, connectUpstream, ledgerWrite } from './core.mjs';

const UPSTREAM_CMD = process.env.AIL_UPSTREAM_CMD || 'node';
const UPSTREAM_ARGS = (process.env.AIL_UPSTREAM_ARGS || '').split(' ').filter(Boolean);

const upstreamTransport = new StdioClientTransport({
  command: UPSTREAM_CMD,
  args: UPSTREAM_ARGS,
  // Upstream credential lives here, in the proxy's environment only.
  env: {
    ...process.env,
    UPSTREAM_API_KEY: process.env.AIL_UPSTREAM_SECRET || 'unset'
  },
  stderr: 'pipe'
});

const upstream = await connectUpstream(upstreamTransport);
ledgerWrite({
  event: 'proxy/start',
  front_end: 'stdio',
  upstream_cmd: `${UPSTREAM_CMD} ${UPSTREAM_ARGS.join(' ')}`,
  upstream_child_pid: upstreamTransport.pid ?? null,
  proxy_pid: process.pid,
  proxy_ppid: process.ppid
});

const server = buildProxyServer(upstream, 'stdio');
await server.connect(new StdioServerTransport());
process.stderr.write('[proxy] stdio proxy ready\n');
