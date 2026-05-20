#!/usr/bin/env node
/**
 * Regression test for the session-resurrection bug (fixed in 1d75780).
 *
 * Runs a realistic claude.ai-style flow against the oauth-proxy on
 * http://127.0.0.1:8080/mcp:
 *
 *   1. initialize → capture session id
 *   2. notifications/initialized
 *   3. open a standalone GET SSE stream and close it (some MCP clients do
 *      this between tool calls — should NOT kill the session)
 *   4. tools/call browser_navigate → https://www.budgetly.com.au
 *   5. 2s idle
 *   6. tools/call browser_snapshot
 *
 * Passes if:
 *   - every response's mcp-session-id header equals the initial session id
 *   - the snapshot result mentions "budgetly" (the navigated page is still open)
 *
 * Usage (inside the running container):
 *   docker exec pmin-mcpinfrastructure-playwright-1 node test-session-persistence.js
 *
 * Requires MCP_AUTH_TOKEN in the env (already set in the container).
 * Exits 0 on pass, 1 on fail.
 */
'use strict';

const http = require('http');

const PORT = parseInt(process.env.PROXY_PORT || '8080', 10);
const TOKEN = (process.env.MCP_AUTH_TOKEN || '').trim();
if (!TOKEN) {
  console.error('MCP_AUTH_TOKEN not set');
  process.exit(1);
}

const baseHeaders = {
  'Content-Type': 'application/json',
  'Accept': 'application/json, text/event-stream',
  'Authorization': 'Bearer ' + TOKEN,
};

function request(method, headers, body) {
  return new Promise((resolve) => {
    const req = http.request(
      { hostname: '127.0.0.1', port: PORT, path: '/mcp', method, headers },
      (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
      }
    );
    req.on('error', (e) => resolve({ status: -1, headers: {}, body: 'ERR:' + e.message }));
    if (body) req.write(body);
    if (method === 'GET') {
      // Hold the SSE stream briefly, then destroy to simulate a client disconnect.
      setTimeout(() => {
        try { req.destroy(); } catch {}
        resolve({ status: 0, headers: {}, body: 'sse-closed' });
      }, 800);
      return;
    }
    req.end();
  });
}

function jsonBody(obj) {
  const s = JSON.stringify(obj);
  return { body: s, length: Buffer.byteLength(s) };
}

function assert(cond, msg) {
  if (!cond) {
    console.error('FAIL:', msg);
    process.exit(1);
  }
  console.log('PASS:', msg);
}

(async () => {
  // 1. initialize
  const init = jsonBody({
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: { name: 'session-persistence-test', version: '1.0.0' },
    },
  });
  const r1 = await request('POST', { ...baseHeaders, 'Content-Length': init.length }, init.body);
  assert(r1.status === 200, `initialize returned 200 (got ${r1.status})`);
  const sid = r1.headers['mcp-session-id'];
  assert(typeof sid === 'string' && sid.length > 0, `initialize response has mcp-session-id (got ${sid})`);

  // 2. notifications/initialized
  const notif = jsonBody({ jsonrpc: '2.0', method: 'notifications/initialized' });
  const r2 = await request(
    'POST',
    { ...baseHeaders, 'Mcp-Session-Id': sid, 'Content-Length': notif.length },
    notif.body
  );
  assert(r2.status === 202, `initialized notification returned 202 (got ${r2.status})`);

  // 3. open + close standalone GET SSE
  const g = await request('GET', { ...baseHeaders, 'Accept': 'text/event-stream', 'Mcp-Session-Id': sid });
  assert(g.body === 'sse-closed', 'GET SSE stream opened and closed without error');

  // 4. navigate
  const nav = jsonBody({
    jsonrpc: '2.0', id: 2, method: 'tools/call',
    params: { name: 'browser_navigate', arguments: { url: 'https://www.budgetly.com.au' } },
  });
  const r3 = await request(
    'POST',
    { ...baseHeaders, 'Mcp-Session-Id': sid, 'Content-Length': nav.length },
    nav.body
  );
  assert(r3.status === 200, `navigate returned 200 (got ${r3.status})`);
  assert(
    r3.headers['mcp-session-id'] === sid,
    `navigate response mcp-session-id matches (${r3.headers['mcp-session-id']} === ${sid})`
  );

  // 5. 2s idle
  await new Promise((r) => setTimeout(r, 2000));

  // 6. snapshot — must still see the navigated page
  const snap = jsonBody({
    jsonrpc: '2.0', id: 3, method: 'tools/call',
    params: { name: 'browser_snapshot', arguments: {} },
  });
  const r4 = await request(
    'POST',
    { ...baseHeaders, 'Mcp-Session-Id': sid, 'Content-Length': snap.length },
    snap.body
  );
  assert(r4.status === 200, `snapshot returned 200 (got ${r4.status})`);
  assert(
    r4.headers['mcp-session-id'] === sid,
    `snapshot response mcp-session-id matches (${r4.headers['mcp-session-id']} === ${sid})`
  );
  assert(
    r4.body.toLowerCase().includes('budgetly'),
    'snapshot body mentions "budgetly" — navigated page still open'
  );

  console.log('\nAll checks passed. Session persisted across init → SSE → navigate → idle → snapshot.');
  process.exit(0);
})().catch((e) => {
  console.error('Unexpected error:', e);
  process.exit(1);
});
