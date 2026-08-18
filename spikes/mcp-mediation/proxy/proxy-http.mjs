// HTTP front end: the proxy is a network service. The agent points at
// http://proxy:8080/mcp. The proxy connects upstream to a real
// @modelcontextprotocol/server-everything running streamableHttp on :3001,
// and it is the only party holding the upstream bearer token.
//
//   agent client  --http-->  proxy :8080  --http-->  upstream :3001

import express from 'express';
import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { buildProxyServer, connectUpstream, ledgerWrite } from './core.mjs';

const PORT = Number(process.env.AIL_PROXY_PORT || 8080);
const UPSTREAM_URL = process.env.AIL_UPSTREAM_URL || 'http://upstream:3001/mcp';
const UPSTREAM_SECRET = process.env.AIL_UPSTREAM_SECRET || 'unset';

const upstreamTransport = new StreamableHTTPClientTransport(new URL(UPSTREAM_URL), {
  requestInit: { headers: { authorization: `Bearer ${UPSTREAM_SECRET}` } }
});
const upstream = await connectUpstream(upstreamTransport);
ledgerWrite({
  event: 'proxy/start',
  front_end: 'http',
  upstream_url: UPSTREAM_URL,
  listen_port: PORT,
  proxy_pid: process.pid
});

const app = express();
app.use(express.json());

// Capture the TCP peer address and expose it to the mediation core. The core
// reads it out of requestInfo.headers, so inject it as a synthetic header.
app.use((req, _res, next) => {
  req.headers['x-ail-peer'] = `${req.socket.remoteAddress}:${req.socket.remotePort}`;
  next();
});

const transports = new Map();

app.all('/mcp', async (req, res) => {
  const sid = req.headers['mcp-session-id'];
  let transport = sid ? transports.get(sid) : undefined;
  if (!transport) {
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: id => {
        transports.set(id, transport);
        ledgerWrite({
          event: 'session/init',
          front_end: 'http',
          mcp_session_id: id,
          tcp_peer: req.headers['x-ail-peer']
        });
      }
    });
    const server = buildProxyServer(upstream, 'http', extra => ({
      tcp_peer: extra?.requestInfo?.headers?.['x-ail-peer'] ?? null
    }));
    await server.connect(transport);
  }
  await transport.handleRequest(req, res, req.body);
});

app.listen(PORT, '0.0.0.0', () => {
  process.stderr.write(`[proxy] http proxy listening on ${PORT}, upstream ${UPSTREAM_URL}\n`);
});
