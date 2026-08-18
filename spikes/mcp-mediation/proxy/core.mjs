// Mediation core shared by the stdio and HTTP proxy front ends.
//
// This is the thing under test: an MCP proxy that sits between an MCP client
// (the agent) and a real off-the-shelf MCP server (the tool). It evaluates every
// tools/call before forwarding it, records it to an append-only JSONL "ledger",
// and records the upstream result on the way back.
//
// Policy under test is deliberately trivial (deny one tool name, deny any call
// whose arguments contain a marker string). The spike is about whether the proxy
// is on the path at all, not about policy expressiveness.

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema
} from '@modelcontextprotocol/sdk/types.js';
import fs from 'node:fs';
import path from 'node:path';

const LEDGER = process.env.AIL_LEDGER || '/ledger/proxy-ledger.jsonl';

export function ledgerWrite(entry) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry });
  try {
    fs.mkdirSync(path.dirname(LEDGER), { recursive: true });
    fs.appendFileSync(LEDGER, line + '\n');
  } catch (e) {
    process.stderr.write(`[proxy] LEDGER WRITE FAILED: ${e.message}\n`);
  }
  process.stderr.write(`[proxy] ${line}\n`);
}

// The one and only policy. Returns null to allow, or a string reason to deny.
export function evaluate(toolName, args) {
  if (toolName === 'get-env') {
    return 'DENY: tool get-env is not permitted (exfiltration risk)';
  }
  const blob = JSON.stringify(args ?? {});
  if (blob.includes('AIL-FORBIDDEN')) {
    return 'DENY: argument contains forbidden marker AIL-FORBIDDEN';
  }
  return null;
}

// Best-effort attribution: everything the proxy can actually learn about who is
// calling. Recorded verbatim so the report can say what is and is not available.
export function attribute(extra, frontEnd) {
  const at = { front_end: frontEnd };
  at.mcp_session_id = extra?.sessionId ?? null;
  at.jsonrpc_request_id = extra?.requestId ?? null;
  at.auth_info = extra?.authInfo ? Object.keys(extra.authInfo) : null;
  const ri = extra?.requestInfo;
  if (ri) {
    at.http_headers_present = Object.keys(ri.headers ?? {});
    at.http_header_authorization = ri.headers?.authorization ? '<present>' : null;
    at.http_header_user_agent = ri.headers?.['user-agent'] ?? null;
    at.http_header_x_forwarded_for = ri.headers?.['x-forwarded-for'] ?? null;
  } else {
    at.http_headers_present = null;
  }
  if (frontEnd === 'stdio') {
    // For stdio the only OS-level facts available are the proxy's own pid and
    // its parent pid, which IS the client process (the client spawned us).
    at.os_pid = process.pid;
    at.os_ppid = process.ppid;
  }
  return at;
}

// Wire a low-level MCP Server (facing the agent) to an upstream Client.
export function buildProxyServer(upstream, frontEnd, peerLookup) {
  const server = new Server(
    { name: 'ail-mediation-proxy', version: '0.0.1' },
    { capabilities: { tools: {}, resources: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const res = await upstream.listTools();
    ledgerWrite({ event: 'tools/list', tool_count: res.tools.length });
    return res;
  });

  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return await upstream.listResources();
  });

  server.setRequestHandler(ReadResourceRequestSchema, async request => {
    return await upstream.readResource(request.params);
  });

  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const toolName = request.params.name;
    const args = request.params.arguments;
    const who = attribute(extra, frontEnd);
    if (peerLookup) Object.assign(who, peerLookup(extra));

    const denyReason = evaluate(toolName, args);
    if (denyReason) {
      ledgerWrite({
        event: 'tools/call',
        decision: 'DENY',
        tool: toolName,
        arguments: args,
        reason: denyReason,
        attribution: who
      });
      // Refusal shape: an MCP tool error result, not a transport error.
      return {
        isError: true,
        content: [{ type: 'text', text: denyReason }]
      };
    }

    ledgerWrite({
      event: 'tools/call',
      decision: 'ALLOW',
      tool: toolName,
      arguments: args,
      attribution: who
    });

    const result = await upstream.callTool({ name: toolName, arguments: args });

    // Return path: can the proxy see the result?
    ledgerWrite({
      event: 'tools/result',
      tool: toolName,
      isError: result.isError ?? false,
      result_preview: JSON.stringify(result).slice(0, 400)
    });

    return result;
  });

  return server;
}

export async function connectUpstream(transport) {
  const client = new Client({ name: 'ail-mediation-proxy-upstream', version: '0.0.1' });
  await client.connect(transport);
  return client;
}
