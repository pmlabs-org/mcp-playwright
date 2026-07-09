#!/usr/bin/env node
/**
 * OAuth 2.0 PKCE proxy for playwright-mcp.
 *
 * Spawns playwright-mcp on an internal port, then exposes:
 *   - OAuth discovery + PKCE auth endpoints on the public PORT
 *   - Bearer token gating on all other paths
 *   - Transparent proxy (including SSE streaming) to the internal MCP server
 *
 * Required env vars:
 *   MCP_AUTH_TOKEN      — shared secret issued as Bearer token after OAuth
 *   OAUTH_CLIENT_ID     — OAuth client ID (use "claude-pathfinder")
 *   OAUTH_CLIENT_SECRET — OAuth client secret
 *
 * Optional env vars:
 *   PORT                — public port (default: 8080)
 */
'use strict';

const http = require('http');
const { createHash, randomUUID } = require('crypto');
const { spawn } = require('child_process');
const { URLSearchParams } = require('url');

const PORT = parseInt(process.env.PORT || '8080', 10);
const INTERNAL_PORT = 8081;
const AUTH_TOKEN = (process.env.MCP_AUTH_TOKEN || '').trim();
const OAUTH_CLIENT_ID = (process.env.OAUTH_CLIENT_ID || 'claude-pathfinder').trim();
const OAUTH_CLIENT_SECRET = (process.env.OAUTH_CLIENT_SECRET || '').trim();

/** @type {Record<string, {codeChallenge:string, codeChallengeMethod:string, redirectUri:string, expiresAt:number}>} */
const authCodes = {};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

function parseFormBody(body) {
  const result = {};
  for (const [k, v] of new URLSearchParams(body)) result[k] = v;
  return result;
}

function json(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

/** Retry until playwright-mcp's HTTP port accepts connections. */
function waitForMcp() {
  return new Promise((resolve) => {
    const check = () => {
      const req = http.request({ hostname: '127.0.0.1', port: INTERNAL_PORT, path: '/' }, () => resolve());
      req.on('error', () => setTimeout(check, 200));
      req.end();
    };
    setTimeout(check, 500);
  });
}

/**
 * Pre-warm Chromium by doing a minimal browser session before the proxy
 * starts accepting external connections. Without this, the first real
 * browser_navigate takes ~60s (Chromium cold start), which exceeds the
 * Anthropic connector's timeout and causes every initial request to fail.
 */
function warmUpBrowser() {
  const makePost = (body, sessionId, earlyFlush = false) => new Promise((resolve, reject) => {
    const b = JSON.stringify(body);
    const hdrs = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',
      'Host': `localhost:${INTERNAL_PORT}`,
      'Content-Length': String(Buffer.byteLength(b)),
    };
    if (sessionId) hdrs['mcp-session-id'] = sessionId;
    const r = http.request(
      { hostname: '127.0.0.1', port: INTERNAL_PORT, path: '/mcp', method: 'POST', headers: hdrs },
      (res) => {
        let d = '';
        let done = false;
        res.on('data', c => {
          d += c;
          // earlyFlush: resolve as soon as the first SSE data: line arrives so we
          // don't block on playwright-mcp holding the stream open after the result.
          if (earlyFlush && !done && d.includes('\ndata: ')) {
            done = true;
            res.destroy();
            resolve({ headers: res.headers, body: d });
          }
        });
        res.on('end', () => { if (!done) resolve({ headers: res.headers, body: d }); });
        res.on('error', () => { if (!done) resolve({ headers: res.headers, body: d }); });
      }
    );
    r.on('error', reject);
    r.write(b);
    r.end();
  });

  return (async () => {
    console.log('Warming up Chromium (first launch may take ~60s)...');
    const t0 = Date.now();
    const r1 = await makePost({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'warmup', version: '1' } } });
    const sid = r1.headers['mcp-session-id'];
    await makePost({ jsonrpc: '2.0', method: 'notifications/initialized' }, sid);
    // Navigate to a real external URL (not about:blank) so Chrome's full
    // network stack — DNS resolver, TLS session cache, HTTP/2 connection pool —
    // is initialised before the first real client request. about:blank skips all
    // of that and the first real external navigate still cold-starts at ~60s.
    await makePost({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'browser_navigate', arguments: { url: 'https://example.com' } } }, sid, true);
    console.log(`Chromium ready in ${Date.now() - t0}ms`);
  })().catch((err) => {
    console.error('Warm-up failed (proceeding anyway):', err.message);
  });
}

/** Forward req → internal playwright-mcp, pipe response back (handles SSE). */
function proxyRequest(req, res) {
  // One-line visibility per /mcp request so session/header flow is debuggable
  // without bringing back a session-rewrite proxy layer.
  if (req.url === '/mcp') {
    console.log('[PROXY]', req.method, req.url,
      'session=' + (req.headers['mcp-session-id'] || 'NONE'),
      'cl=' + (req.headers['content-length'] || 'none'),
      'te=' + (req.headers['transfer-encoding'] || 'none'),
      'extra-headers=' + JSON.stringify(Object.keys(req.headers).filter(
        h => !['host','content-type','accept','content-length','transfer-encoding','mcp-session-id'].includes(h)
      )));
  }

  // Forward only the headers playwright-mcp needs. Forwarding all incoming
  // headers (e.g. accept-encoding, connection, x-forwarded-for, etc.) can
  // cause playwright-mcp to stall — empirically observed as 60s delays on
  // browser_navigate even with a warm Chromium, while direct calls are <1s.
  const headers = {
    host: `localhost:${INTERNAL_PORT}`,
    'content-type': req.headers['content-type'] || 'application/json',
    accept: req.headers['accept'] || 'application/json, text/event-stream',
  };
  if (req.headers['content-length']) headers['content-length'] = req.headers['content-length'];
  if (req.headers['transfer-encoding']) headers['transfer-encoding'] = req.headers['transfer-encoding'];
  if (req.headers['mcp-session-id']) headers['mcp-session-id'] = req.headers['mcp-session-id'];

  const opts = {
    hostname: '127.0.0.1',
    port: INTERNAL_PORT,
    path: req.url,
    method: req.method,
    headers,
  };

  // Buffer the full request body before forwarding.
  // This lets us detect content-length mismatches and log what playwright-mcp receives.
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    const reqBody = Buffer.concat(chunks);
    if (req.url === '/mcp') {
      const clHeader = parseInt(req.headers['content-length'] || '0', 10);
      if (clHeader && clHeader !== reqBody.length) {
        console.warn('[REQ BODY MISMATCH]', 'cl-header=' + clHeader, 'actual=' + reqBody.length);
      }
      console.log('[REQ BODY]', 'session=' + (req.headers['mcp-session-id'] || 'NONE'),
        'len=' + reqBody.length);
    }

    // For 'initialize' requests: Anthropic's connector sends capabilities.roots,
    // which causes playwright-mcp to call server.listRoots() inside initializeServer().
    // With no GET SSE channel, listRoots() blocks for 60s before its catch handler
    // fires — making every subsequent tool call time out. Strip 'roots' so playwright-mcp
    // skips listRoots() entirely.
    let forwardBody = reqBody;
    if (reqBody.length > 0 && req.url === '/mcp') {
      try {
        const parsed = JSON.parse(reqBody.toString());
        if (parsed.method === 'initialize' && parsed.params?.capabilities?.roots !== undefined) {
          delete parsed.params.capabilities.roots;
          forwardBody = Buffer.from(JSON.stringify(parsed));
          console.log('[PROXY] stripped capabilities.roots from initialize, session=' + (req.headers['mcp-session-id'] || 'NONE'));
        }
      } catch (_) { /* not JSON — forward as-is */ }
    }

    // Overwrite content-length with the actual body size in case Caddy mismatches.
    if (forwardBody.length > 0) {
      headers['content-length'] = String(forwardBody.length);
      delete headers['transfer-encoding'];
    }

  const proxy = http.request(opts, (proxyRes) => {
    const ct = proxyRes.headers['content-type'] || '';
    const isSSE = ct.includes('text/event-stream');
    if (req.url === '/mcp') {
      console.log('[PROXY RESP]', req.method, proxyRes.statusCode,
        'ct=' + ct, 'session=' + (req.headers['mcp-session-id'] || 'NONE'));
    }

    if (proxyRes.statusCode >= 400) {
      let body = '';
      proxyRes.on('data', chunk => { body += chunk; });
      proxyRes.on('end', () => {
        console.error(`Upstream ${proxyRes.statusCode} for ${req.method} ${req.url}: ${body.slice(0, 500)}`);
        if (!res.headersSent) {
          res.writeHead(proxyRes.statusCode, proxyRes.headers);
          res.end(body);
        }
      });
      proxyRes.on('error', (err) => {
        console.error('proxyRes error:', err.message);
        if (!res.headersSent) json(res, 502, { error: 'bad_gateway' });
        else try { res.destroy(); } catch (_) {}
      });
      return;
    }

    // POST SSE responses: convert to application/json and respond immediately
    // when the first complete SSE data line arrives.
    //
    // playwright-mcp v0.0.77 changed all POST responses to text/event-stream.
    // Anthropic's claude.ai connector only processes application/json for POST
    // results (text/event-stream in the Accept header is for GET SSE streams).
    // Additionally, playwright-mcp holds the SSE stream open after the result
    // event (acting as a persistent channel), so waiting for proxyRes.on('end')
    // would stall for ~60s before we could forward the result.
    if (req.method === 'POST' && isSSE) {
      let buf = '';
      let responded = false;
      const flush = () => {
        if (responded) return;
        const match = buf.match(/^data: (.+)$/m);
        if (!match) return;
        responded = true;
        const jsonBody = match[1];
        const sid = req.headers['mcp-session-id'] || 'NONE';
        console.log('[PROXY] POST SSE→JSON', 'session=' + sid, 'bytes=' + jsonBody.length);
        const outHeaders = { ...proxyRes.headers };
        outHeaders['content-type'] = 'application/json';
        outHeaders['content-length'] = String(Buffer.byteLength(jsonBody));
        delete outHeaders['transfer-encoding'];
        res.writeHead(proxyRes.statusCode, outHeaders);
        res.end(jsonBody);
        proxyRes.resume(); // drain remaining SSE stream to prevent backpressure
      };
      proxyRes.on('data', chunk => { buf += chunk.toString(); flush(); });
      proxyRes.on('end', flush); // fallback if stream closes before data: line seen
      // drain on client-close to prevent backpressure killing the session
      res.on('close', () => { if (!responded) responded = true; proxyRes.resume(); });
      proxyRes.on('error', (err) => {
        console.error('proxyRes error:', err.message);
        if (!res.headersSent) json(res, 502, { error: 'bad_gateway' });
        else try { res.destroy(); } catch (_) {}
      });
      return;
    }

    // GET SSE (and any non-SSE): pipe with drain on client-close to prevent
    // backpressure from killing the playwright-mcp session.
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res, { end: true });
    if (req.method === 'GET' || isSSE) {
      res.on('close', () => {
        proxyRes.unpipe(res);
        proxyRes.resume();
      });
    }
    proxyRes.on('error', (err) => {
      console.error('proxyRes error:', err.message);
      if (!res.headersSent) json(res, 502, { error: 'bad_gateway' });
      else try { res.destroy(); } catch (_) {}
    });
  });
  proxy.on('error', (err) => {
    console.error('Proxy error:', err.message);
    if (!res.headersSent) json(res, 502, { error: 'bad_gateway' });
    else res.destroy();
  });
  if (forwardBody.length > 0) proxy.write(forwardBody);
  proxy.end();
  }); // end req.on('end')
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;

  try {
    // Health check (no auth required)
    if (path === '/health' && req.method === 'GET') {
      json(res, 200, { status: 'ok' });
      return;
    }

    // OAuth Protected Resource Metadata
    if (path === '/.well-known/oauth-protected-resource' && req.method === 'GET') {
      const base = `https://${req.headers.host}`;
      json(res, 200, { resource: `${base}/mcp`, authorization_servers: [base] });
      return;
    }

    // OAuth Authorization Server Metadata
    if (path === '/.well-known/oauth-authorization-server' && req.method === 'GET') {
      const base = `https://${req.headers.host}`;
      json(res, 200, {
        issuer: base,
        authorization_endpoint: `${base}/authorize`,
        token_endpoint: `${base}/oauth/token`,
        grant_types_supported: ['authorization_code', 'client_credentials'],
        code_challenge_methods_supported: ['S256'],
        response_types_supported: ['code'],
      });
      return;
    }

    // Authorization endpoint
    if (path === '/authorize' && req.method === 'GET') {
      const response_type = url.searchParams.get('response_type');
      const client_id = url.searchParams.get('client_id');
      const redirect_uri = url.searchParams.get('redirect_uri');
      const code_challenge = url.searchParams.get('code_challenge');
      const code_challenge_method = url.searchParams.get('code_challenge_method') || 'S256';
      const state = url.searchParams.get('state');

      if (client_id !== OAUTH_CLIENT_ID) { json(res, 401, { error: 'invalid_client' }); return; }
      if (response_type !== 'code') { json(res, 400, { error: 'unsupported_response_type' }); return; }
      if (!code_challenge) { json(res, 400, { error: 'code_challenge_required' }); return; }

      const code = randomUUID();
      authCodes[code] = {
        codeChallenge: code_challenge,
        codeChallengeMethod: code_challenge_method,
        redirectUri: redirect_uri,
        expiresAt: Date.now() + 5 * 60 * 1000,
      };

      const redirectUrl = new URL(redirect_uri);
      redirectUrl.searchParams.set('code', code);
      if (state) redirectUrl.searchParams.set('state', state);
      res.writeHead(302, { Location: redirectUrl.toString() });
      res.end();
      return;
    }

    // Token endpoint
    if (path === '/oauth/token' && req.method === 'POST') {
      if (!OAUTH_CLIENT_ID || !AUTH_TOKEN) { json(res, 500, { error: 'server_misconfigured' }); return; }

      const bodyRaw = await readBody(req);
      const contentType = req.headers['content-type'] || '';
      const body = contentType.includes('application/json') ? JSON.parse(bodyRaw) : parseFormBody(bodyRaw);
      const grant_type = body.grant_type;

      if (grant_type === 'authorization_code') {
        const { code, code_verifier, redirect_uri } = body;
        const stored = authCodes[code];
        if (!stored || stored.expiresAt < Date.now()) { json(res, 400, { error: 'invalid_grant' }); return; }
        const expected = createHash('sha256').update(code_verifier).digest('base64url');
        if (expected !== stored.codeChallenge) { json(res, 400, { error: 'invalid_grant' }); return; }
        if (redirect_uri && redirect_uri !== stored.redirectUri) { json(res, 400, { error: 'invalid_grant' }); return; }
        delete authCodes[code];
        json(res, 200, { access_token: AUTH_TOKEN, token_type: 'Bearer', expires_in: 86400 });
        return;
      }

      // client_credentials grant
      if (!OAUTH_CLIENT_SECRET) { json(res, 500, { error: 'server_misconfigured' }); return; }
      let client_id, client_secret;
      const basicAuth = req.headers['authorization'];
      if (basicAuth && basicAuth.startsWith('Basic ')) {
        const decoded = Buffer.from(basicAuth.slice(6), 'base64').toString();
        const colon = decoded.indexOf(':');
        client_id = decoded.slice(0, colon);
        client_secret = decoded.slice(colon + 1);
      } else {
        client_id = body.client_id;
        client_secret = body.client_secret;
      }
      if (client_id !== OAUTH_CLIENT_ID || client_secret !== OAUTH_CLIENT_SECRET) {
        json(res, 401, { error: 'invalid_client' }); return;
      }
      json(res, 200, { access_token: AUTH_TOKEN, token_type: 'Bearer', expires_in: 86400 });
      return;
    }

    // Bearer token enforcement for all other routes
    if (AUTH_TOKEN) {
      const authHeader = req.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        const host = req.headers.host;
        res.writeHead(401, {
          'WWW-Authenticate': `Bearer resource_metadata="https://${host}/.well-known/oauth-protected-resource"`,
          'Content-Type': 'application/json',
        });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }
      if (authHeader.slice(7) !== AUTH_TOKEN) {
        res.writeHead(401, { 'WWW-Authenticate': 'Bearer error="invalid_token"', 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }
    }

    // Proxy to internal playwright-mcp (handles SSE via pipe)
    proxyRequest(req, res);

  } catch (err) {
    console.error('Server error:', err);
    if (!res.headersSent) json(res, 500, { error: 'internal_server_error' });
  }
});

// ---------------------------------------------------------------------------
// Start playwright-mcp on internal port
// ---------------------------------------------------------------------------

const mcpProcess = spawn('node', [
  'cli.js',
  '--headless', '--browser', 'chromium', '--no-sandbox',
  '--shared-browser-context',
  '--port', String(INTERNAL_PORT), '--host', '127.0.0.1',
], { stdio: 'inherit' });

mcpProcess.on('exit', (code) => {
  console.error(`playwright-mcp exited with code ${code}`);
  process.exit(code ?? 1);
});

process.on('SIGTERM', () => {
  mcpProcess.kill('SIGTERM');
  server.close(() => process.exit(0));
});

// ---------------------------------------------------------------------------
// Start proxy after MCP is ready
// ---------------------------------------------------------------------------

waitForMcp()
  .then(() => warmUpBrowser())
  .then(() => {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`OAuth proxy listening on port ${PORT} → playwright-mcp on port ${INTERNAL_PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to start:', err);
    process.exit(1);
  });
