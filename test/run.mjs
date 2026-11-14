#!/usr/bin/env node
// Runs gwproxy.mjs against two local stand-ins, one for api.anthropic.com and one for a gateway,
// and checks what each of them received. Nothing leaves this machine and no real key is used.
//
//   node test/run.mjs            about three minutes (one stream is held open for 150 seconds)
//   node test/run.mjs --quick    the same without the long stream
//
// Needs openssl, and a system that lets an ordinary user listen on port 443 (macOS does), because
// the proxy always connects to api.anthropic.com on that port.
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const script = process.env.GWPROXY_TEST_SCRIPT || path.join(here, '..', 'plugin', 'gwproxy.mjs');   // another copy, to check that these checks can fail
const quick = process.argv.includes('--quick');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gwproxy-test-'));
const f = (n) => path.join(tmp, n);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const GATEWAY_KEY = 'test-gateway-key-0000';
const LOGIN = 'Bearer client-login-token';
const MB = 1024 * 1024;

// --- a CA for the stand-ins, and one certificate naming both of them
const ssl = (...a) => execFileSync('openssl', a, { stdio: ['ignore', 'ignore', 'pipe'] });
fs.writeFileSync(f('ca.cnf'), '[req]\ndistinguished_name=dn\nprompt=no\nx509_extensions=v3\n[dn]\nCN=gwproxy test CA\n[v3]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n');
fs.writeFileSync(f('leaf.cnf'), '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=stand-in\n[v3]\nsubjectAltName=DNS:api.anthropic.com,DNS:localhost\nextendedKeyUsage=serverAuth\n');
ssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', f('ca.key'), '-out', f('ca.pem'), '-config', f('ca.cnf'));
ssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', f('leaf.key'), '-out', f('leaf.csr'), '-config', f('leaf.cnf'));
ssl('x509', '-req', '-days', '2', '-in', f('leaf.csr'), '-CA', f('ca.pem'), '-CAkey', f('ca.key'), '-CAcreateserial', '-out', f('leaf.pem'), '-extfile', f('leaf.cnf'), '-extensions', 'v3');
const standInTls = { key: fs.readFileSync(f('leaf.key')), cert: fs.readFileSync(f('leaf.pem')) };

// --- the stand-ins. Each keeps a record of every request it received.
const seen = { anthropic: [], gateway: [] };
const closed = new Set();
const readAll = (req) => new Promise((resolve) => { const c = []; req.on('data', (d) => c.push(d)).on('end', () => resolve(Buffer.concat(c))); });
function record(side, req, body) {
  let modelShaped = false;
  try { const j = JSON.parse(body); modelShaped = typeof j.model === 'string' && (Array.isArray(j.messages) || 'prompt' in j); } catch { /* not JSON */ }
  seen[side].push({ method: req.method, url: req.url, headers: req.headers, modelShaped });
}

const anthropic = https.createServer(standInTls, async (req, res) => {
  const url = new URL(req.url, 'https://x');
  if (url.pathname === '/api/upload') {   // hashed as it arrives, never held
    const h = crypto.createHash('sha256'); let n = 0;
    req.on('data', (d) => { h.update(d); n += d.length; }).on('end', () => { record('anthropic', req, ''); res.end(JSON.stringify({ bytes: n, sha256: h.digest('hex') })); });
    return;
  }
  const body = await readAll(req);
  record('anthropic', req, body);
  if (url.pathname === '/api/ping') return res.end(JSON.stringify({ path: req.url, authorization: req.headers.authorization || null, echoed: body.length }));
  if (url.pathname === '/api/sse') {
    const n = Number(url.searchParams.get('n')); const ms = Number(url.searchParams.get('ms'));
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    for (let i = 0; i < n; i++) { res.write(`data: ${i}\n\n`); await sleep(ms); }
    return res.end();
  }
  if (url.pathname === '/api/download') {
    const mb = Number(url.searchParams.get('mb')); const block = Buffer.alloc(MB, 'd');
    res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': mb * MB });
    for (let i = 0; i < mb; i++) if (!res.write(block)) await new Promise((r) => res.once('drain', r));
    return res.end();
  }
  if (url.pathname === '/api/status') { res.writeHead(Number(url.searchParams.get('code'))); return res.end(); }
  if (url.pathname === '/api/headers') { res.writeHead(200, { 'set-cookie': 'kept=1', connection: 'keep-alive, x-one-hop', 'x-one-hop': 'secret', 'x-end-to-end': 'yes' }); return res.end('{}'); }
  if (url.pathname === '/api/reset') { res.writeHead(200, { 'content-type': 'text/plain' }); res.write('partial'); await sleep(100); return req.socket.destroy(); }
  if (url.pathname === '/api/hang') { req.socket.on('close', () => closed.add(url.searchParams.get('id'))); return; }
  res.writeHead(404); res.end('{}');
});
anthropic.on('upgrade', (req, sock) => {   // answers 101, then sends back whatever it gets
  record('anthropic', req, '');
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nserver-first;');
  sock.on('data', (d) => sock.write(d)); sock.on('error', () => {}); sock.on('end', () => sock.end());
});

const gateway = https.createServer(standInTls, async (req, res) => {
  const body = await readAll(req);
  record('gateway', req, body);
  let j = {};
  try { j = JSON.parse(body); } catch { /* count as empty */ }
  if (req.url.startsWith('/v1/messages/count_tokens')) return res.end(JSON.stringify({ input_tokens: body.length }));
  if (j.model === 'fail-500') { res.writeHead(500, { 'content-type': 'application/json' }); return res.end('{"type":"error","error":{"type":"api_error","message":"gateway says no"}}'); }
  if (j.model === 'fail-429') { res.writeHead(429, { 'retry-after': '7', 'content-type': 'application/json' }); return res.end('{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}'); }
  if (j.stream) {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'set-cookie': 'from-gateway=1' });
    for (let i = 0; i < 5; i++) { res.write(`event: content_block_delta\ndata: {"i":${i}}\n\n`); await sleep(150); }
    return res.end();
  }
  res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'from-gateway=1' });
  res.end(JSON.stringify({ id: 'msg_test', model: j.model, got_bytes: body.length, sha256: sha(body) }));
});

const listen = (server, port, host) => new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, () => { server.off('error', reject); resolve(server.address().port); }); });
try { await listen(anthropic, 443, '127.0.0.1'); }
catch { try { await listen(anthropic, 443, '0.0.0.0'); } catch (e) { console.error(`cannot listen on port 443 (${e.code}); this test needs that, see the top of the file`); process.exit(2); } }
const gatewayPort = await listen(gateway, 0, '127.0.0.1');

// --- the proxy under test, with its own folder, on its own port
const home = f('home');
fs.writeFileSync(f('gateway.env'), `ANTHROPIC_BASE_URL=https://localhost:${gatewayPort}\nANTHROPIC_API_KEY=${GATEWAY_KEY}\n`, { mode: 0o600 });
const proxyPort = await new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
const env = { ...process.env, GWPROXY_HOME: home, NODE_EXTRA_CA_CERTS: f('ca.pem') };
for (const k of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy']) delete env[k];
const set = spawnSync(process.execPath, [script, 'setup', '--gateway-env', f('gateway.env'), '--port', String(proxyPort)], { env, encoding: 'utf8' });
assert.equal(set.status, 0, set.stderr);
let proxyOut = '';
const proxy = spawn(process.execPath, ['--import', path.join(here, 'resolve-local.mjs'), script, 'serve'], { env });
proxy.stdout.on('data', (d) => { proxyOut += d; }); proxy.stderr.on('data', (d) => { proxyOut += d; });
for (let i = 0; i < 50 && !proxyOut.includes('listening'); i++) await sleep(100);
assert.match(proxyOut, /listening/, `the proxy did not start: ${proxyOut}`);
const proxyCa = fs.readFileSync(path.join(home, 'ca.pem'));
const rssMb = () => Number(execFileSync('ps', ['-o', 'rss=', '-p', String(proxy.pid)], { encoding: 'utf8' })) / 1024;

// --- a client that goes through the proxy the way Claude Code does
const tunnel = (target = 'api.anthropic.com:443') => new Promise((resolve, reject) => {
  const sock = net.connect(proxyPort, '127.0.0.1');
  let head = '';
  sock.once('error', reject);
  sock.on('data', function onData(d) {
    head += d.toString('latin1');
    if (!head.includes('\r\n\r\n')) return;
    sock.off('data', onData);
    if (!head.startsWith('HTTP/1.1 200')) return reject(new Error(head.split('\r\n')[0]));
    const t = tls.connect({ socket: sock, servername: 'api.anthropic.com', ca: proxyCa, ALPNProtocols: ['http/1.1'] }, () => resolve(t));
    t.once('error', reject);
  });
  sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
});
class ThroughProxy extends http.Agent { createConnection(_o, cb) { tunnel().then((s) => cb(null, s), cb); } }
const agent = new ThroughProxy({ keepAlive: true });
function call({ method = 'GET', path: p, headers = {}, body, useAgent = agent, onData, expectContinue = false }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ agent: useAgent, host: 'api.anthropic.com', method, path: p, headers: { authorization: LOGIN, cookie: 'session=client-cookie', ...headers } }, (res) => {
      const chunks = []; const at = []; const t0 = Date.now();
      res.on('data', (d) => { at.push(Date.now() - t0); if (onData) onData(d); else chunks.push(d); });
      res.on('end', () => { const buf = Buffer.concat(chunks); let json = null; try { json = JSON.parse(buf); } catch { /* not JSON */ } resolve({ status: res.statusCode, headers: res.headers, body: buf, json, at }); });
      res.on('error', reject);
    });
    req.on('error', reject);
    if (expectContinue) { req.on('continue', () => req.end(body)); return; }
    if (body && typeof body.pipe === 'function') body.pipe(req); else req.end(body);
  });
}
const json = (o) => JSON.stringify(o);
const J = { 'content-type': 'application/json' };
const modelBody = (extra = {}) => json({ model: 'test-model', max_tokens: 8, messages: [{ role: 'user', content: 'hi' }], ...extra });

// --- the checks
const results = [];
async function check(name, fn) {
  const t0 = Date.now();
  try { await fn(); results.push([true, name, Date.now() - t0]); console.log(`ok    ${name} (${Date.now() - t0} ms)`); }
  catch (e) { results.push([false, name]); console.log(`FAIL  ${name}\n      ${String(e.message).split('\n')[0]}`); }
}

let longStream = null;
if (!quick) longStream = (async () => { const r = await call({ path: '/api/sse?n=150&ms=1000', useAgent: new ThroughProxy() }); return r; })();

await check('a model call goes to the gateway with the gateway key, without the login or cookie', async () => {
  const r = await call({ method: 'POST', path: '/v1/messages?beta=true', headers: J, body: modelBody() });
  assert.equal(r.status, 200); assert.equal(r.json.id, 'msg_test');
  const g = seen.gateway.at(-1);
  assert.equal(g.headers.authorization, `Bearer ${GATEWAY_KEY}`); assert.equal(g.headers.cookie, undefined); assert.equal(g.url, '/v1/messages?beta=true');
  assert.equal(r.headers['set-cookie'], undefined, 'a cookie from the gateway reached the client');
});
await check('a gzip model call arrives at the gateway decompressed and intact', async () => {
  const plain = Buffer.from(modelBody({ pad: 'x'.repeat(50_000) }));
  const { gzipSync } = await import('node:zlib');
  const r = await call({ method: 'POST', path: '/v1/messages', headers: { ...J, 'content-encoding': 'gzip' }, body: gzipSync(plain) });
  assert.equal(r.json.sha256, sha(plain)); assert.equal(seen.gateway.at(-1).headers['content-encoding'], undefined);
});
await check('a streamed model call arrives in pieces, not all at once', async () => {
  const r = await call({ method: 'POST', path: '/v1/messages', headers: J, body: modelBody({ stream: true }) });
  assert.ok(r.at.length >= 4, `only ${r.at.length} chunks`); assert.ok(r.at.at(-1) - r.at[0] > 400, 'the chunks arrived together');
});
await check('token counting goes to the gateway', async () => {
  const r = await call({ method: 'POST', path: '/v1/messages/count_tokens', headers: J, body: modelBody() });
  assert.ok(r.json.input_tokens > 0);
});
await check('gateway errors (500, 429) reach the client as they are', async () => {
  const a = await call({ method: 'POST', path: '/v1/messages', headers: J, body: modelBody({ model: 'fail-500' }) });
  const b = await call({ method: 'POST', path: '/v1/messages', headers: J, body: modelBody({ model: 'fail-429' }) });
  assert.equal(a.status, 500); assert.equal(b.status, 429); assert.equal(b.headers['retry-after'], '7');
});
await check('a thread continue is refused by the proxy and reaches neither side', async () => {
  const before = [seen.gateway.length, seen.anthropic.length];
  const r = await call({ method: 'POST', path: '/v1/messages', headers: J, body: modelBody({ thread: { type: 'continue' } }) });
  assert.equal(r.status, 400); assert.equal(r.json.error.details.error_code, 'thread_unsupported_request');
  assert.deepEqual([seen.gateway.length, seen.anthropic.length], before);
});
await check('a pass-list request reaches Anthropic unchanged, with the login', async () => {
  const r = await call({ method: 'POST', path: '/api/ping?x=1', headers: J, body: json({ events: [1, 2, 3] }) });
  assert.equal(r.json.authorization, LOGIN); assert.equal(r.json.path, '/api/ping?x=1'); assert.equal(r.json.echoed, json({ events: [1, 2, 3] }).length);
  assert.equal(seen.anthropic.at(-1).headers.cookie, 'session=client-cookie');
});
await check('unlisted paths, the tripwire and odd request targets are refused and reach neither side', async () => {
  const before = [seen.gateway.length, seen.anthropic.length];
  assert.equal((await call({ method: 'POST', path: '/v1/something_new', headers: J, body: modelBody() })).status, 404);
  assert.equal((await call({ path: '/v1/models' })).status, 404);
  assert.equal((await call({ method: 'POST', path: '/api/ping', headers: J, body: modelBody() })).status, 403);
  assert.equal((await call({ method: 'POST', path: '/v1/./messages', headers: J, body: modelBody() })).status, 400);
  assert.equal((await call({ method: 'POST', path: '/v1/%6dessages', headers: J, body: modelBody() })).status, 404);
  assert.deepEqual([seen.gateway.length, seen.anthropic.length], before);
});
await check('responses with no body pass (HEAD, 204, 304)', async () => {
  assert.equal((await call({ method: 'HEAD', path: '/api/ping' })).status, 200);
  assert.equal((await call({ path: '/api/status?code=204' })).status, 204);
  assert.equal((await call({ path: '/api/status?code=304' })).status, 304);
});
await check('response headers: Anthropic cookies kept, headers named in Connection dropped', async () => {
  const r = await call({ path: '/api/headers' });
  assert.deepEqual(r.headers['set-cookie'], ['kept=1']); assert.equal(r.headers['x-end-to-end'], 'yes'); assert.equal(r.headers['x-one-hop'], undefined);
});
await check('Expect: 100-continue', async () => {
  const r = await call({ method: 'POST', path: '/api/ping', headers: { ...J, expect: '100-continue' }, body: json({ a: 1 }), expectContinue: true });
  assert.equal(r.status, 200); assert.equal(r.json.echoed, 7);
});
await check('50 requests in a row on one connection', async () => {
  const one = new ThroughProxy({ keepAlive: true, maxSockets: 1 }); let tunnels = 0;
  const make = one.createConnection.bind(one); one.createConnection = (o, cb) => { tunnels++; make(o, cb); };
  for (let i = 0; i < 50; i++) assert.equal((await call({ path: `/api/ping?i=${i}`, useAgent: one })).json.path, `/api/ping?i=${i}`);
  assert.equal(tunnels, 1, `${tunnels} connections were opened`); one.destroy();
});
await check('three requests written at once are answered in order', async () => {
  const t = await tunnel(); let got = '';
  t.on('data', (d) => { got += d; });
  t.write([1, 2, 3].map((i) => `GET /api/ping?p=${i} HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n`).join(''));
  for (let i = 0; i < 50 && (got.match(/"path"/g) || []).length < 3; i++) await sleep(100);
  assert.deepEqual([...got.matchAll(/ping\?p=(\d)/g)].map((m) => m[1]), ['1', '2', '3']); t.destroy();
});
await check('a 200 MB upload is streamed: it arrives intact and the proxy does not hold it', async () => {
  const block = Buffer.alloc(MB, 'u'); const h = crypto.createHash('sha256'); const before = rssMb(); let peak = before;
  const watch = setInterval(() => { peak = Math.max(peak, rssMb()); }, 100);
  const { Readable } = await import('node:stream');
  const src = Readable.from((function* gen() { for (let i = 0; i < 200; i++) { h.update(block); yield block; } })());
  const r = await call({ method: 'POST', path: '/api/upload', headers: { 'content-type': 'application/octet-stream' }, body: src });
  clearInterval(watch);
  assert.equal(r.json.bytes, 200 * MB); assert.equal(r.json.sha256, h.digest('hex'));
  assert.ok(peak - before < 120, `the proxy grew by ${Math.round(peak - before)} MB`);
});
await check('a 200 MB download is streamed: it arrives whole and the proxy does not hold it', async () => {
  const before = rssMb(); let peak = before; let n = 0;
  const watch = setInterval(() => { peak = Math.max(peak, rssMb()); }, 100);
  const r = await call({ path: '/api/download?mb=200', onData: (d) => { n += d.length; } });
  clearInterval(watch);
  assert.equal(r.status, 200); assert.equal(n, 200 * MB); assert.ok(peak - before < 120, `the proxy grew by ${Math.round(peak - before)} MB`);
});
await check('an upgraded connection carries bytes both ways, including bytes sent with the handshake', async () => {
  const t = await tunnel(); let got = Buffer.alloc(0);
  t.on('data', (d) => { got = Buffer.concat([got, d]); });
  t.write('GET /v1/code/sessions/x/ws HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nAuthorization: ' + LOGIN + '\r\n\r\nearly;');
  for (let i = 0; i < 30 && !got.includes('early;'); i++) await sleep(100);
  assert.ok(got.toString().startsWith('HTTP/1.1 101'), got.toString().slice(0, 40)); assert.ok(got.includes('server-first;'), 'the bytes the server sent first did not arrive');
  const big = crypto.randomBytes(3 * MB); const mark = got.length; t.write(big);
  for (let i = 0; i < 100 && got.length < mark + big.length; i++) await sleep(100);
  assert.equal(sha(got.subarray(mark)), sha(big));
  for (let i = 0; i < 5; i++) { const m = got.length; t.write(`ping${i};`); await sleep(700); assert.equal(got.subarray(m).toString(), `ping${i};`); }
  t.end(); assert.equal(seen.anthropic.at(-1).headers.authorization, LOGIN);
});
await check('an upgrade on a path that is not on the pass list is refused', async () => {
  const t = await tunnel(); let got = '';
  t.on('data', (d) => { got += d; }); t.on('error', () => {});
  const before = seen.anthropic.length;
  t.write('GET /v1/realtime HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
  for (let i = 0; i < 20 && !got; i++) await sleep(100);
  assert.ok(got.startsWith('HTTP/1.1 403'), got.slice(0, 30)); assert.equal(seen.anthropic.length, before); t.destroy();
});
await check('when the client goes away, the proxy drops its request to Anthropic', async () => {
  const id = crypto.randomUUID(); const one = new ThroughProxy();
  const p = call({ path: `/api/hang?id=${id}`, useAgent: one }).catch(() => {});
  await sleep(400); one.destroy(); await p;
  for (let i = 0; i < 30 && !closed.has(id); i++) await sleep(100);
  assert.ok(closed.has(id), 'the request was still open on the other side after 3 seconds');
});
await check('when Anthropic drops a response half way, the client sees a failure and the proxy carries on', async () => {
  await assert.rejects(call({ path: '/api/reset', useAgent: new ThroughProxy() }));
  assert.equal((await call({ path: '/api/ping' })).status, 200);
});
await check('bodies that are too large or cannot be read are refused, and the next request still works', async () => {
  const { gzipSync } = await import('node:zlib'); const before = [seen.gateway.length, seen.anthropic.length];
  const bomb = gzipSync(Buffer.alloc(100 * MB));
  assert.equal((await call({ method: 'POST', path: '/v1/messages', headers: { ...J, 'content-encoding': 'gzip' }, body: bomb })).status, 415);
  assert.equal((await call({ method: 'POST', path: '/api/ping', headers: { ...J, 'content-encoding': 'gzip' }, body: bomb })).status, 415);
  const big = Buffer.alloc(40 * MB, 'a');
  for (const p of ['/v1/messages', '/api/ping']) {   // the proxy answers 413 and closes; either is a refusal
    const r = await call({ method: 'POST', path: p, headers: J, body: big, useAgent: new ThroughProxy() }).catch((e) => ({ status: e.code }));
    assert.ok(r.status === 413 || ['EPIPE', 'ECONNRESET'].includes(r.status), `got ${r.status}`);
  }
  assert.deepEqual([seen.gateway.length, seen.anthropic.length], before);
  assert.equal((await call({ path: '/api/ping' })).status, 200);
});
await check('malformed tunnel requests are refused without stopping the proxy', async () => {
  for (const target of ['example.invalid:65536', 'example.invalid:0', 'no-port', 'api.anthropic.com:99999999']) await assert.rejects(tunnel(target));
  assert.equal((await call({ path: '/api/ping' })).status, 200);
});
await check('"api.anthropic.com." with a trailing dot is intercepted like the plain name', async () => {
  const t = await tunnel('api.anthropic.com.:443'); let got = '';
  t.on('data', (d) => { got += d; });
  t.write('GET /v1/models HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n');
  for (let i = 0; i < 20 && !got; i++) await sleep(100);
  assert.ok(got.startsWith('HTTP/1.1 404'), 'it was not read by the proxy'); t.destroy();
});
await check('200 requests at once, model calls and pass-list calls mixed, each answered correctly', async () => {
  const many = new ThroughProxy({ keepAlive: true, maxSockets: 40 });
  const out = await Promise.all(Array.from({ length: 200 }, (_, i) => (i % 2
    ? call({ method: 'POST', path: '/v1/messages', headers: J, body: modelBody({ model: `m-${i}` }), useAgent: many }).then((r) => r.json.model === `m-${i}`)
    : call({ path: `/api/ping?n=${i}`, useAgent: many }).then((r) => r.json.path === `/api/ping?n=${i}` && r.json.authorization === LOGIN))));
  assert.equal(out.filter(Boolean).length, 200); many.destroy();
});
await check('with the gateway gone, a model call fails at the proxy and nothing goes to Anthropic', async () => {
  await new Promise((r) => { gateway.close(r); gateway.closeAllConnections(); });
  const before = seen.anthropic.length;
  const r = await call({ method: 'POST', path: '/v1/messages', headers: J, body: modelBody(), useAgent: new ThroughProxy() });
  assert.equal(r.status, 502); assert.equal(seen.anthropic.length, before);
});
if (longStream) await check('an event stream held open for 150 seconds delivers every event as it is sent', async () => {
  const r = await longStream;
  const events = r.body.toString().split('\n\n').filter(Boolean);
  assert.equal(events.length, 150); assert.equal(events.at(-1), 'data: 149');
  const gaps = r.at.slice(1).map((t, i) => t - r.at[i]); const worst = Math.max(...gaps);
  assert.ok(r.at.length >= 140, `events arrived in only ${r.at.length} pieces`); assert.ok(worst < 2500, `one gap was ${worst} ms`);
});

// --- what must hold across everything above
await check('across the whole run: the login never reached the gateway', async () => {
  for (const g of seen.gateway) { assert.equal(g.headers.authorization, `Bearer ${GATEWAY_KEY}`); assert.equal(g.headers.cookie, undefined); assert.equal(g.headers['x-api-key'], undefined); }
  assert.ok(seen.gateway.length > 100);
});
await check('across the whole run: the gateway key never reached Anthropic, and no model call did', async () => {
  for (const a of seen.anthropic) { assert.ok(!JSON.stringify(a.headers).includes(GATEWAY_KEY)); assert.equal(a.modelShaped, false, `${a.method} ${a.url}`); assert.ok(!a.url.startsWith('/v1/messages')); }
  assert.ok(seen.anthropic.length > 100);
});
await check('the proxy is still running, and its log has no crash and no key or login in it', async () => {
  assert.equal(proxy.exitCode, null); assert.ok(!proxyOut.includes('FATAL'), proxyOut.split('\n').find((l) => l.includes('FATAL')));
  assert.ok(!proxyOut.includes(GATEWAY_KEY) && !proxyOut.includes('client-login-token') && !proxyOut.includes('client-cookie'));
});

proxy.kill(); anthropic.close(); anthropic.closeAllConnections(); agent.destroy();
fs.rmSync(tmp, { recursive: true, force: true });
const failed = results.filter(([ok]) => !ok).length;
console.log(`\n${results.length - failed} of ${results.length} passed`);
process.exit(failed ? 1 : 0);
