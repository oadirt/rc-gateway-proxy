#!/usr/bin/env node
// gwproxy: a local forward proxy that sends Claude Code's model calls to a gateway and leaves
// everything else alone. Claude Code runs unmodified, signed in to its own account, with
// HTTPS_PROXY pointing here and NODE_EXTRA_CA_CERTS naming this proxy's CA.
//
//   api.anthropic.com   /v1/messages and below      -> the gateway, gateway key in place of the login
//   api.anthropic.com   a path on the pass list      -> api.anthropic.com, unchanged, unless its body
//                       (PASS_PREFIXES, below)          looks like a model call: then refused
//   api.anthropic.com   any other path               -> refused here with 404, and logged as "unlisted"
//   any other host                                   -> tunnelled, never read
//
// The pass list is what Claude Code needs to sign in, to load its configuration and to run Remote
// Control. Anything not on it never reaches Anthropic, so a model call on a path this file has not
// heard of fails here instead of running on the account.
//
// Commands: install and uninstall do everything; setup, service, settings are their steps; serve is
// the proxy; status and hook report on it. No dependencies. openssl is called once, for the certificates.
// The login service is launchd on macOS and a systemd user unit on Linux.
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import zlib from 'node:zlib';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ANTHROPIC = 'api.anthropic.com';
const HOME = process.env.GWPROXY_HOME || path.join(os.homedir(), '.config', 'gwproxy');
// A second copy, kept in another folder, is a service of its own.
const LABEL = process.env.GWPROXY_HOME ? `local.gwproxy.${crypto.createHash('sha256').update(HOME).digest('hex').slice(0, 8)}` : 'local.gwproxy';
const P = { config: path.join(HOME, 'config.json'), ca: path.join(HOME, 'ca.pem'), leaf: path.join(HOME, 'leaf.pem'), key: path.join(HOME, 'leaf.key') };
const BODY_CAP = 32 * 1024 * 1024;      // largest body read here, as sent: a model call, or JSON on its way to Anthropic
const DECODED_CAP = 64 * 1024 * 1024;   // and once decompressed
const CONNECT_MS = 30_000;              // to reach the other side
const HEADERS_MS = 15 * 60_000;         // for the other side to start answering
const GATEWAY_PREFIXES = ['/v1/messages'];
const PASS_PREFIXES = ['/api', '/mcp-registry', '/v1/code', '/v1/environments', '/v1/sessions', '/v1/mcp_servers', '/v1/oauth', '/v1/session_ingress', '/v2/session_ingress', '/v2/ccr-sessions'];
const HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade']);

const die = (msg) => { console.error(`gwproxy: ${msg}`); process.exit(1); };
const pathOf = (url) => { const q = url.indexOf('?'); return q < 0 ? url : url.slice(0, q); };
const under = (p, prefixes) => prefixes.some((x) => p === x || p.startsWith(`${x}/`));
const family = (p) => p.split('/').slice(0, 3).join('/');

// Where a request to api.anthropic.com goes. A target that could be read two ways is not guessed at.
function classify(url, passPrefixes) {
  if (typeof url !== 'string' || url[0] !== '/') return { route: 'bad', path: '(not a path)' };
  const p = pathOf(url);
  if (p.includes('//') || p.includes('\\') || /%(2f|2e|5c|00)/i.test(p) || p.split('/').some((seg) => seg === '.' || seg === '..')) return { route: 'bad', path: p };
  const low = p.toLowerCase();
  if (under(low, GATEWAY_PREFIXES)) return { route: 'gateway', path: p, low };
  if (under(low, passPrefixes)) return { route: 'pass', path: p, low };
  return { route: 'unlisted', path: p, low };
}

function readConfig() {
  let c;
  try { c = JSON.parse(fs.readFileSync(P.config, 'utf8')); } catch { die(`no usable ${P.config}; run: gwproxy.mjs setup --gateway-env FILE`); }
  const extra = Array.isArray(c.passPrefixes) ? c.passPrefixes.filter((x) => typeof x === 'string' && /^\/[a-z0-9_\/-]+$/.test(x)).map((x) => x.replace(/\/+$/, '')) : [];
  return { port: c.port || 3457, gatewayEnv: c.gatewayEnv, passPrefixes: [...PASS_PREFIXES, ...extra], installedEnv: c.installedEnv };
}

// The gateway's URL and key, from a file of ANTHROPIC_BASE_URL= and ANTHROPIC_API_KEY= lines.
function readGateway(file) {
  const text = fs.readFileSync(file, 'utf8');
  const get = (name) => { const m = text.match(new RegExp(`^\\s*(?:export\\s+)?${name}=(.*)$`, 'm')); return m ? m[1].trim().replace(/^["']|["']$/g, '') : ''; };
  let url;
  try { url = new URL(get('ANTHROPIC_BASE_URL')); } catch { throw new Error(`${file} has no usable ANTHROPIC_BASE_URL`); }
  const key = get('ANTHROPIC_API_KEY') || get('ANTHROPIC_AUTH_TOKEN');
  if (!key) throw new Error(`${file} has no ANTHROPIC_API_KEY`);
  if (url.protocol !== 'https:') throw new Error('the gateway URL must be https');
  if (url.hostname === ANTHROPIC) throw new Error('the gateway URL is Anthropic itself');
  return { url, key };
}

// Decompresses a body, giving up (by throwing) once the result would pass DECODED_CAP.
function decode(buf, encoding) {
  const enc = (encoding || '').trim().toLowerCase();
  const o = { maxOutputLength: DECODED_CAP };
  if (!enc || enc === 'identity') return buf;
  if (enc === 'gzip' || enc === 'x-gzip') return zlib.gunzipSync(buf, o);
  if (enc === 'deflate') return zlib.inflateSync(buf, o);
  if (enc === 'br') return zlib.brotliDecompressSync(buf, o);
  if (enc === 'zstd' && zlib.zstdDecompressSync) return zlib.zstdDecompressSync(buf, o);
  throw new Error(`unsupported content-encoding ${enc}`);
}

// A JSON body with a model and a conversation or prompt is a model call, whatever its path.
// 'unreadable' means the body could not be decompressed, so nothing can be said about it.
function looksLikeModelCall(buf, encoding) {
  let plain;
  try { plain = decode(buf, encoding); } catch { return 'unreadable'; }
  try {
    const j = JSON.parse(plain);
    return !!j && typeof j === 'object' && !Array.isArray(j) && typeof j.model === 'string'
      && (Array.isArray(j.messages) || 'prompt' in j || 'input' in j) ? 'yes' : 'no';
  } catch { return 'no'; }
}

// Reads a request body. Resolves null, leaving the request paused, if it is larger than BODY_CAP.
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    const done = (fn, v) => { req.off('data', onData); req.off('end', onEnd); req.off('error', onError); req.off('close', onClose); fn(v); };
    const onData = (c) => { chunks.push(c); size += c.length; if (size > BODY_CAP) { req.pause(); done(resolve, null); } };
    const onEnd = () => done(resolve, Buffer.concat(chunks));
    const onError = (e) => done(reject, e);
    const onClose = () => { if (!req.complete) done(reject, new Error('client went away')); };
    req.on('data', onData); req.on('end', onEnd); req.on('error', onError); req.on('close', onClose);
  });
}

// close: the request body was not read to its end, so the connection cannot be used again.
function sendError(res, status, type, message, details, close = false) {
  if (res.headersSent) { res.destroy(); return; }
  res.writeHead(status, { 'content-type': 'application/json', 'x-should-retry': 'false', ...(close ? { connection: 'close' } : {}) });
  res.end(JSON.stringify({ type: 'error', error: { type, message, ...(details ? { details } : {}) } }), () => { if (close) res.socket?.destroySoon(); });
}
const hasBody = (req) => !['GET', 'HEAD'].includes(req.method);
const namedInConnection = (value) => new Set(String(value || '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean));

function serve() {
  const cfg = readConfig();
  let gw;
  try { gw = readGateway(cfg.gatewayEnv); } catch (e) { die(e.message); }
  let secure, leafEnds;
  try {
    const leaf = fs.readFileSync(P.leaf);
    secure = tls.createSecureContext({ key: fs.readFileSync(P.key), cert: leaf });
    leafEnds = new Date(new crypto.X509Certificate(leaf).validTo);
  } catch { die('no certificates; run: gwproxy.mjs setup'); }
  const gwPrefix = gw.url.pathname.replace(/\/+$/, '');
  const agents = { gateway: new https.Agent({ keepAlive: true }), anthropic: new https.Agent({ keepAlive: true }) };
  const stats = { started: new Date().toISOString(), gateway: 0, anthropic: 0, refused: 0, unlisted: 0, threadRefused: 0, tunnels: 0, upgrades: 0, errors: 0 };
  const unlistedFamilies = new Map();   // path family -> times refused, so a missing pass-list entry can be seen
  const tunnelHosts = new Map();        // host -> tunnels opened
  const count = (map, key) => { if (map.has(key) || map.size < 500) map.set(key, (map.get(key) || 0) + 1); };
  const note = (tag, text) => console.log(`${new Date().toISOString()} ${tag.padEnd(9)} ${text}`);
  // One line per request to Anthropic's host: no headers, no bodies, no query strings.
  const log = (route, req, status, started) => note(route, `${req.method} ${pathOf(req.url)} ${status} ${Date.now() - started}ms`);
  const refuse = (req, res, started, status, type, message, close = false) => { stats.refused++; log('refused', req, status, started); sendError(res, status, type, message, undefined, close); };

  const copyHeaders = (req, drop = []) => {
    const h = {}; const named = namedInConnection(req.headers.connection);
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k) && !named.has(k) && k !== 'host' && !drop.includes(k)) h[k] = v;
    return h;
  };

  // Sends the request on and streams the answer back as it arrives.
  function relay({ req, res, route, host, port, urlPath, headers, body, started }) {
    const up = https.request({ agent: agents[route], host, port, method: req.method, path: urlPath, headers, servername: net.isIP(host) ? undefined : host }, (r) => {
      clearTimeout(headerTimer);
      const h = { ...r.headers };
      for (const k of [...HOP, ...namedInConnection(r.headers.connection)]) delete h[k];
      if (route === 'gateway') delete h['set-cookie'];
      res.writeHead(r.statusCode, h);
      res.flushHeaders();
      r.pipe(res);
      r.on('end', () => log(route, req, r.statusCode, started));
      r.on('error', () => res.destroy());
    });
    const giveUp = (code) => up.destroy(Object.assign(new Error(code), { code }));
    const headerTimer = setTimeout(() => giveUp('NO_ANSWER'), HEADERS_MS);
    up.on('close', () => clearTimeout(headerTimer));
    up.on('socket', (sock) => {
      if (!sock.connecting) return;   // a kept-alive connection, already open
      const t = setTimeout(() => giveUp('CONNECT_TIMEOUT'), CONNECT_MS);
      sock.once('secureConnect', () => clearTimeout(t)); sock.once('close', () => clearTimeout(t));
    });
    let clientGone = false;
    up.on('error', (e) => {
      if (clientGone) { log(route, req, 'client-closed', started); return; }
      stats.errors++;
      log(route, req, `failed:${e.code || 'error'}`, started);
      // Never answered from the other side: a model call that cannot reach the gateway fails here.
      sendError(res, 502, 'api_error', `gwproxy: could not reach ${route === 'gateway' ? 'the gateway' : ANTHROPIC} (${e.code || 'error'})`);
    });
    res.on('close', () => { if (!res.writableFinished) { clientGone = true; up.destroy(); } });
    if (body) up.end(body); else req.pipe(up);
  }

  async function modelCall(req, res, p, started) {
    const sent = await readBody(req);
    if (!sent) return refuse(req, res, started, 413, 'request_too_large', 'gwproxy: request body too large', true);
    let body;
    try { body = decode(sent, req.headers['content-encoding']); }
    catch (e) { return refuse(req, res, started, 415, 'invalid_request_error', `gwproxy: the request body could not be decompressed (${e.code || e.message})`); }
    if (req.method === 'POST' && p === '/v1/messages') {
      let j = null;
      try { j = JSON.parse(body); } catch { /* the gateway will say so */ }
      // Signed in to its own account, Claude Code sends only the new part of a conversation after
      // the first turn. A gateway that picks an account per request cannot continue that, so this
      // is refused the way Anthropic refuses it, and the client sends the conversation in full.
      if (j?.thread?.type === 'continue') {
        stats.threadRefused++; log('thread', req, 400, started);
        return sendError(res, 400, 'invalid_request_error', 'thread: the gateway keeps no thread state; resend the conversation', { error_code: 'thread_unsupported_request' });
      }
    }
    const headers = copyHeaders(req, ['authorization', 'x-api-key', 'cookie', 'content-encoding', 'content-length']);
    headers.authorization = `Bearer ${gw.key}`;
    if (hasBody(req)) headers['content-length'] = String(body.length);
    stats.gateway++;
    relay({ req, res, route: 'gateway', host: gw.url.hostname, port: gw.url.port || 443, urlPath: gwPrefix + req.url, headers, body, started });
  }

  async function passThrough(req, res, p, started) {
    const type = (req.headers['content-type'] || '').toLowerCase();
    let body = null;   // null: streamed on without being read (uploads and the like)
    if (hasBody(req) && (!type || type.includes('json') || type.startsWith('text/'))) {
      body = await readBody(req);
      if (!body) return refuse(req, res, started, 413, 'request_too_large', 'gwproxy: a body this large cannot be checked, so it was not sent on', true);
      const verdict = looksLikeModelCall(body, req.headers['content-encoding']);
      if (verdict === 'unreadable') return refuse(req, res, started, 415, 'invalid_request_error', 'gwproxy: the request body could not be decompressed, so it was not sent on');
      if (verdict === 'yes') {
        note('TRIPWIRE', `a request to ${p} looks like a model call and was not sent to Anthropic`);
        return refuse(req, res, started, 403, 'permission_error', `gwproxy: ${p} looks like a model call; only /v1/messages is sent to the gateway, and nothing like it is sent to Anthropic`);
      }
    }
    stats.anthropic++;
    relay({ req, res, route: 'anthropic', host: ANTHROPIC, port: 443, urlPath: req.url, headers: copyHeaders(req), body, started });
  }

  // What Claude Code sent to api.anthropic.com, in the clear.
  const inner = http.createServer({ requestTimeout: 0, keepAliveTimeout: 120_000 }, (req, res) => {
    const started = Date.now(); const c = classify(req.url, cfg.passPrefixes);
    if (c.route === 'bad') { stats.refused++; note('refused', `${req.method} a request target that could be read two ways 400`); return sendError(res, 400, 'invalid_request_error', 'gwproxy: unusual request target refused', undefined, hasBody(req)); }
    if (c.route === 'unlisted') {
      stats.unlisted++; count(unlistedFamilies, family(c.low)); log('unlisted', req, 404, started);
      return sendError(res, 404, 'not_found_error', `gwproxy: ${c.path} is not on the list of paths sent to Anthropic, and is not a model call`, undefined, hasBody(req));
    }
    (c.route === 'gateway' ? modelCall(req, res, c.low, started) : passThrough(req, res, c.path, started)).catch((e) => {
      stats.errors++; log('error', req, e.message, started); sendError(res, 502, 'api_error', 'gwproxy: request failed', undefined, true);
    });
  });
  inner.on('upgrade', (req, sock, head) => {   // WebSockets: passed through as bytes
    const started = Date.now();
    sock.on('error', () => {});
    const c = classify(req.url, cfg.passPrefixes);
    if (c.route !== 'pass') {
      stats.refused++; if (c.route === 'unlisted') count(unlistedFamilies, family(c.low));
      note('refused', `${req.method} upgrade ${c.path} (${c.route}) 403`);
      sock.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return;
    }
    stats.upgrades++;
    const up = tls.connect({ host: ANTHROPIC, port: 443, servername: ANTHROPIC, ALPNProtocols: ['http/1.1'] }, () => {
      clearTimeout(connectTimer);
      let raw = `${req.method} ${req.url} HTTP/1.1\r\n`;
      for (let i = 0; i < req.rawHeaders.length; i += 2) raw += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`;
      up.write(raw + '\r\n'); if (head?.length) up.write(head);
      up.pipe(sock); sock.pipe(up);
      log('upgrade', req, 'open', started);
    });
    const connectTimer = setTimeout(() => up.destroy(Object.assign(new Error('timeout'), { code: 'CONNECT_TIMEOUT' })), CONNECT_MS);
    up.on('error', (e) => { log('upgrade', req, `failed:${e.code || 'error'}`, started); sock.destroy(); });
    up.on('close', () => { clearTimeout(connectTimer); sock.destroy(); }); sock.on('close', () => up.destroy());
  });
  inner.on('clientError', (_e, sock) => sock.destroy());

  const outer = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/gwproxy/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, pid: process.pid, gatewayHost: gw.url.host, certificateEnds: leafEnds.toISOString(), ...stats, unlistedFamilies: Object.fromEntries(unlistedFamilies), tunnelHosts: Object.fromEntries(tunnelHosts) }));
    }
    res.writeHead(400, { 'content-type': 'text/plain' }); res.end('gwproxy is an HTTPS forward proxy; set HTTPS_PROXY to this address\n');
  });
  outer.on('connect', (req, sock, head) => {
    sock.on('error', () => {});
    try {
      const m = /^\[?([^\]]+?)\]?:(\d{1,5})$/.exec(req.url || '');
      const port = m ? Number(m[2]) : 0;
      if (!m || port < 1 || port > 65535) { sock.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); return; }
      const host = m[1].toLowerCase().replace(/\.+$/, '');   // "api.anthropic.com." is the same host
      if (host === ANTHROPIC && port === 443) {
        sock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head?.length) sock.unshift(head);
        const t = new tls.TLSSocket(sock, { isServer: true, secureContext: secure, ALPNProtocols: ['http/1.1'] });
        t.on('error', () => {});
        inner.emit('connection', t);
        return;
      }
      stats.tunnels++; count(tunnelHosts, host);
      let open = false;
      const up = net.connect(port, host, () => {
        open = true; up.setTimeout(0);
        sock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head?.length) up.write(head);
        up.pipe(sock); sock.pipe(up);
      });
      up.setTimeout(CONNECT_MS, () => up.destroy());
      up.on('error', () => { if (!open) sock.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'); else sock.destroy(); });
      up.on('close', () => sock.destroy()); sock.on('close', () => up.destroy());
    } catch (e) {
      stats.errors++; note('error', `CONNECT refused: ${e.code || e.message}`);
      sock.destroy();
    }
  });
  outer.on('clientError', (_e, sock) => sock.destroy());
  outer.on('error', (e) => die(`cannot listen on 127.0.0.1:${cfg.port}: ${e.code || e.message}`));
  outer.listen(cfg.port, '127.0.0.1', () => {
    note('gwproxy', `listening on 127.0.0.1:${cfg.port}; model calls go to ${gw.url.host}; certificate ends ${leafEnds.toISOString().slice(0, 10)}`);
    const days = Math.floor((leafEnds - Date.now()) / 86_400_000);
    if (days < 30) note('WARNING', `the certificate ends in ${days} days; run: gwproxy.mjs setup --renew, then gwproxy.mjs service install, then restart Claude Code sessions`);
  });
  process.on('uncaughtException', (e) => { note('FATAL', e.stack || e); process.exit(1); });
  for (const s of ['SIGTERM', 'SIGINT']) process.on(s, () => process.exit(0));
}

// A CA and one certificate for api.anthropic.com. The CA's private key is deleted once the
// certificate is signed, so nothing else can ever be issued under that CA.
function makeCertificates() {
  const tmp = fs.mkdtempSync(path.join(HOME, 'make-'));
  const f = (n) => path.join(tmp, n);
  const ssl = (...args) => execFileSync('openssl', args, { stdio: ['ignore', 'ignore', 'pipe'] });
  try {
    fs.writeFileSync(f('ca.cnf'), '[req]\ndistinguished_name=dn\nprompt=no\nx509_extensions=v3_ca\n[dn]\nCN=gwproxy local CA\n[v3_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign\nsubjectKeyIdentifier=hash\n');
    fs.writeFileSync(f('leaf.cnf'), `[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=${ANTHROPIC}\n[v3_leaf]\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:${ANTHROPIC}\n`);
    ssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '3650', '-keyout', f('ca.key'), '-out', f('ca.pem'), '-config', f('ca.cnf'));
    ssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', f('leaf.key'), '-out', f('leaf.csr'), '-config', f('leaf.cnf'));
    ssl('x509', '-req', '-sha256', '-days', '397', '-in', f('leaf.csr'), '-CA', f('ca.pem'), '-CAkey', f('ca.key'), '-CAcreateserial', '-out', f('leaf.pem'), '-extfile', f('leaf.cnf'), '-extensions', 'v3_leaf');
    fs.chmodSync(f('leaf.key'), 0o600);
    fs.renameSync(f('leaf.key'), P.key); fs.renameSync(f('leaf.pem'), P.leaf); fs.renameSync(f('ca.pem'), P.ca);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}

function setup(args) {
  const opt = (name) => { const i = args.indexOf(name); return i < 0 ? undefined : args[i + 1]; };
  fs.mkdirSync(HOME, { recursive: true, mode: 0o700 });
  let cfg = {};
  try { cfg = JSON.parse(fs.readFileSync(P.config, 'utf8')); } catch { /* first run */ }
  if (opt('--gateway-env')) cfg.gatewayEnv = path.resolve(opt('--gateway-env'));
  if (opt('--port')) cfg.port = Number(opt('--port'));
  cfg.port ||= 3457;
  if (!cfg.gatewayEnv) die('setup needs --gateway-env FILE the first time');
  let gw;
  try { gw = readGateway(cfg.gatewayEnv); } catch (e) { die(e.message); }
  fs.writeFileSync(P.config, JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
  if (args.includes('--renew') || !fs.existsSync(P.leaf) || !fs.existsSync(P.key) || !fs.existsSync(P.ca)) { makeCertificates(); console.log(`made a new CA and certificate in ${HOME}; a running proxy keeps the old one until it is restarted (gwproxy.mjs service install), and Claude Code sessions must be restarted after that`); }
  console.log(`gateway ${gw.url.host} (key read from ${cfg.gatewayEnv}, not shown); port ${cfg.port}`);
}

const scriptPath = fileURLToPath(import.meta.url);
// The login service: launchd on macOS, a systemd user unit on Linux.
const NAME = LABEL.slice('local.'.length);
const mac = process.platform === 'darwin';
const servicePath = mac
  ? path.join(os.homedir(), 'Library', 'LaunchAgents', `${LABEL}.plist`)
  : path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'systemd', 'user', `${NAME}.service`);
const logPath = path.join(os.homedir(), 'Library', 'Logs', `${NAME}.log`);   // macOS; on Linux the log is the user journal
const run = (cmd, ...args) => spawnSync(cmd, args, { encoding: 'utf8' });

function service(action) {
  if (!mac && process.platform !== 'linux') die('the service is written for macOS and Linux only; elsewhere keep "gwproxy.mjs serve" running yourself');
  if (action !== 'install' && action !== 'uninstall') die('usage: gwproxy.mjs service install|uninstall');
  const domain = mac ? `gui/${process.getuid()}` : null;
  if (action === 'uninstall') {
    if (mac) run('launchctl', 'bootout', `${domain}/${LABEL}`);
    else { run('systemctl', '--user', 'disable', '--now', `${NAME}.service`); }
    fs.rmSync(servicePath, { force: true });
    if (!mac) run('systemctl', '--user', 'daemon-reload');
    console.log('service removed'); return;
  }
  // Everything the proxy needs to start is checked before the running one is stopped.
  const cfg = readConfig();
  try { readGateway(cfg.gatewayEnv); } catch (e) { die(e.message); }
  for (const f of [P.ca, P.leaf, P.key]) if (!fs.existsSync(f)) die(`${f} is missing; run: gwproxy.mjs setup`);
  if (run(process.execPath, '--check', scriptPath).status !== 0) die('this script does not parse; the running service was left alone');
  fs.mkdirSync(path.dirname(servicePath), { recursive: true });
  if (mac) installLaunchd(domain); else installSystemd();
}

function installLaunchd(domain) {
  try { fs.closeSync(fs.openSync(logPath, 'a', 0o600)); fs.chmodSync(logPath, 0o600); } catch { /* launchd will create it */ }
  run('launchctl', 'bootout', `${domain}/${LABEL}`);
  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const env = process.env.GWPROXY_HOME ? `  <key>EnvironmentVariables</key>\n  <dict>\n    <key>GWPROXY_HOME</key>\n    <string>${esc(HOME)}</string>\n  </dict>\n` : '';
  fs.writeFileSync(servicePath, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${esc(process.execPath)}</string>
    <string>${esc(scriptPath)}</string>
    <string>serve</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${esc(logPath)}</string>
  <key>StandardErrorPath</key>
  <string>${esc(logPath)}</string>
  <key>Umask</key>
  <integer>63</integer>
${env}</dict>
</plist>
`);
  // bootout is not instant; the name must be free before it can be loaded again.
  let r;
  for (let i = 0; i < 20; i++) { r = run('launchctl', 'bootstrap', domain, servicePath); if (r.status === 0) break; spawnSync('sleep', ['0.5']); }
  if (r.status !== 0) die(`launchctl could not load the service: ${(r.stderr || '').trim()}`);
  console.log(`service installed: ${servicePath}\nlog: ${logPath}`);
}

function installSystemd() {
  // Without a user service manager (some containers, some remote logins) there is nothing to install into.
  if (run('systemctl', '--user', 'show-environment').status !== 0) die(`systemd has no user service manager in this session, so no service was installed. Keep "node ${scriptPath} serve" running yourself, then run "node ${scriptPath} settings enable"`);
  // One word of a unit file: quoted, with systemd's own special characters made literal.
  const word = (s) => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/%/g, '%%').replace(/\$/g, '$$$$')}"`;
  const env = process.env.GWPROXY_HOME ? `Environment=${word(`GWPROXY_HOME=${HOME}`)}\n` : '';
  fs.writeFileSync(servicePath, `[Unit]
Description=gwproxy: Claude Code model calls to a gateway
After=network-online.target

[Service]
ExecStart=${word(process.execPath)} ${word(scriptPath)} serve
Restart=always
RestartSec=2
UMask=0077
${env}
[Install]
WantedBy=default.target
`);
  for (const args of [['daemon-reload'], ['enable', `${NAME}.service`], ['restart', `${NAME}.service`]]) {
    const r = run('systemctl', '--user', ...args);
    if (r.status !== 0) die(`systemctl --user ${args.join(' ')} failed: ${(r.stderr || '').trim()}`);
  }
  console.log(`service installed: ${servicePath}\nlog: journalctl --user -u ${NAME}`);
  const linger = run('loginctl', 'show-user', os.userInfo().username, '-p', 'Linger').stdout || '';
  if (!linger.includes('Linger=yes')) console.log(`note: it runs while you are logged in. To keep it running after you log out, and start it at boot: loginctl enable-linger ${os.userInfo().username}`);
}

function settingsFile() { return path.join(process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude'), 'settings.json'); }

// Why the proxy lines cannot go into a settings file as it stands, or null.
function settingsProblem(j, ours) {
  for (const k of ['ANTHROPIC_BASE_URL', 'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN']) if (j.env?.[k]) return `sets ${k}; remove it first, or Remote Control stays off`;
  if (j.apiKeyHelper) return 'sets apiKeyHelper; remove it first';
  for (const [k, v] of Object.entries(ours)) if (j.env?.[k] && j.env[k] !== v) return `already sets ${k} to something else; not overwriting it`;
  return null;
}
const proxyEnv = (port) => ({ HTTPS_PROXY: `http://127.0.0.1:${port}`, NODE_EXTRA_CA_CERTS: P.ca });
const readSettings = () => { try { return JSON.parse(fs.readFileSync(settingsFile(), 'utf8')); } catch { return {}; } };
const sameFile = (a, b) => { try { return fs.readFileSync(a).equals(fs.readFileSync(b)); } catch { return false; } };
// What the proxy answers on its health address, or null if it does not.
const health = (port, ms = 3000) => new Promise((resolve) => {
  const req = http.get({ host: '127.0.0.1', port, path: '/gwproxy/health', timeout: ms }, (r) => {
    let s = ''; r.on('data', (d) => { s += d; }); r.on('end', () => { try { resolve(JSON.parse(s)); } catch { resolve(null); } });
  });
  req.on('timeout', () => req.destroy()); req.on('error', () => resolve(null));
});

// Points every Claude Code session of this user at the proxy, or takes that back.
function settings(action) {
  const cfg = readConfig();
  const ours = proxyEnv(cfg.port);
  const file = settingsFile();
  const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '{}\n';
  const j = JSON.parse(text);
  const indent = (text.match(/\n([ \t]+)"/) || [])[1] ?? '  ';
  if (action === 'enable') {
    const problem = settingsProblem(j, ours);
    if (problem) die(`${file} ${problem}`);
    j.env = { ...(j.env || {}), ...ours };
  } else if (action === 'disable') {
    // Also what an earlier enable wrote, if the port or folder has changed since.
    for (const written of [ours, cfg.installedEnv || {}]) for (const [k, v] of Object.entries(written)) if (j.env?.[k] === v) delete j.env[k];
    if (j.env && !Object.keys(j.env).length) delete j.env;
  } else die('usage: gwproxy.mjs settings enable|disable');
  const left = Object.keys(ours).filter((k) => action === 'disable' && j.env?.[k]);
  const out = JSON.stringify(j, null, indent) + '\n';
  if (out !== text) {
    const existed = fs.existsSync(file);
    if (existed) { const backup = `${file}.before-gwproxy-${new Date().toISOString().replace(/[:.]/g, '-')}`; fs.copyFileSync(file, backup); console.log(`backup: ${backup}`); }
    const tmp = `${file}.tmp${process.pid}`;
    fs.writeFileSync(tmp, out, { mode: existed ? fs.statSync(file).mode & 0o777 : 0o600, flag: 'wx' });
    // Claude Code writes this file too. If it changed since it was read, nothing is replaced.
    if ((existed ? fs.readFileSync(file, 'utf8') : '{}\n') !== text) { fs.rmSync(tmp, { force: true }); die(`${file} changed while it was being edited; nothing was written, run the command again`); }
    fs.renameSync(tmp, file);
    console.log(`${file}: ${action === 'enable' ? `env now sets ${Object.keys(ours).join(' and ')}` : 'proxy settings removed'}`);
  } else console.log(`${file} already as wanted`);
  if (action === 'enable') {
    const c = JSON.parse(fs.readFileSync(P.config, 'utf8')); c.installedEnv = ours;
    fs.writeFileSync(P.config, JSON.stringify(c, null, 2) + '\n', { mode: 0o600 });
  }
  if (left.length) console.log(`note: ${left.join(' and ')} still set in ${file}, to a value gwproxy did not write; Claude Code still uses a proxy`);
}

const pointedAt = (port) => { const env = readSettings().env || {}; return Object.entries(proxyEnv(port)).every(([k, v]) => env[k] === v); };

async function status() {
  const cfg = readConfig();
  console.log(`settings: Claude Code is ${pointedAt(cfg.port) ? '' : 'not '}pointed at the proxy (${settingsFile()})`);
  const h = await health(cfg.port);
  if (!h) { console.log(`proxy:    not answering on 127.0.0.1:${cfg.port}`); process.exitCode = 1; return; }
  console.log(`proxy:    running, pid ${h.pid}, since ${h.started}, gateway ${h.gatewayHost}`);
  console.log(`requests: ${h.gateway} to the gateway, ${h.anthropic} to Anthropic, ${h.unlisted} unlisted, ${h.refused} refused, ${h.threadRefused} thread continues refused, ${h.upgrades} WebSockets, ${h.tunnels} tunnels to other hosts, ${h.errors} errors`);
  const fams = Object.entries(h.unlistedFamilies || {});
  if (fams.length) console.log(`unlisted: ${fams.map(([k, n]) => `${k} (${n})`).join(', ')}  <- refused with 404; add to "passPrefixes" in ${P.config} only if it is not a model call`);
  const near = Object.keys(h.tunnelHosts || {}).filter((x) => /(^|\.)(anthropic\.com|claude\.ai|claude\.com|claudeusercontent\.com)$/.test(x));
  if (near.length) console.log(`tunnelled, not read: ${near.join(', ')}`);
  console.log(`certificate ends ${h.certificateEnds.slice(0, 10)}`);
}

// Everything, in order, on a machine that may or may not have it already. The proxy is run from a
// copy of this file in the gwproxy folder, so the file it was installed from can move or be updated.
async function install(args) {
  if (!mac && process.platform !== 'linux') die('install is written for macOS and Linux only; elsewhere run setup and settings enable, and keep "gwproxy.mjs serve" running yourself');
  const opt = (name) => { const i = args.indexOf(name); return i < 0 ? undefined : args[i + 1]; };
  const installed = path.join(HOME, 'gwproxy.mjs');
  const kept = path.join(HOME, 'gateway.env');
  const self = (...a) => { const r = spawnSync(process.execPath, [installed, ...a], { stdio: 'inherit' }); if (r.status !== 0) process.exit(r.status || 1); };
  let before = {};
  try { before = JSON.parse(fs.readFileSync(P.config, 'utf8')); } catch { /* first time */ }
  const port = Number(opt('--port')) || before.port || 3457;
  const problem = settingsProblem(readSettings(), proxyEnv(port));
  if (problem) die(`${settingsFile()} ${problem}`);   // before anything is changed
  fs.mkdirSync(HOME, { recursive: true, mode: 0o700 });
  let changed = false;
  // The key file is copied in, so the one that was handed over can be deleted.
  const given = opt('--gateway-env') && path.resolve(opt('--gateway-env'));
  if (given && given !== kept) {
    try { readGateway(given); } catch (e) { die(e.message); }
    if (!sameFile(given, kept)) { fs.copyFileSync(given, kept); changed = true; }
    fs.chmodSync(kept, 0o600);
  }
  const gatewayEnv = given ? kept : before.gatewayEnv;
  if (!gatewayEnv) die('install needs --gateway-env FILE the first time');
  if (scriptPath !== installed && !sameFile(scriptPath, installed)) { fs.copyFileSync(scriptPath, installed); fs.chmodSync(installed, 0o700); changed = true; }
  if (gatewayEnv !== before.gatewayEnv || port !== before.port || ![P.ca, P.leaf, P.key].every((f) => fs.existsSync(f))) changed = true;
  self('setup', '--gateway-env', gatewayEnv, '--port', String(port));
  // The running proxy is only restarted when something it uses has changed.
  if (changed || !fs.existsSync(servicePath) || !(await health(port))) self('service', 'install');
  else console.log('the proxy is running and nothing changed; left as it is');
  self('settings', 'enable');
  for (let i = 0; i < 20 && !(await health(port, 500)); i++) spawnSync('sleep', ['0.5']);
  self('status');
  console.log(`\ninstalled in ${HOME}. Claude Code sessions started from now on send their model calls to the gateway; ones already running pick it up as well.`);
}

function uninstall() {
  if (fs.existsSync(P.config)) settings('disable');
  if (mac || process.platform === 'linux') service('uninstall');
  console.log(`${HOME} (configuration, the key file, certificates) was left in place; delete it to remove the rest`);
}

// For Claude Code's session-start hook: says nothing when all is well, and otherwise one line the
// user is shown. When run from a plugin, this file is the plugin's copy, which shows an update.
async function hook() {
  const say = (text) => console.log(JSON.stringify({ systemMessage: `gwproxy: ${text}` }));
  if (!fs.existsSync(P.config)) return say('not set up on this machine, so this session runs on your own Claude plan. Run /gwproxy:setup with the path of your gateway .env file.');
  const cfg = readConfig(); const installed = path.join(HOME, 'gwproxy.mjs');
  if (!pointedAt(cfg.port)) return say('Claude Code is not pointed at the proxy, so this session runs on your own Claude plan. Run /gwproxy:setup.');
  if (!(await health(cfg.port, 1500))) return say('the proxy is not answering, so model calls will fail. Run /gwproxy:status.');
  if (scriptPath !== installed && fs.existsSync(installed) && !sameFile(scriptPath, installed)) return say('an update is ready. Run /gwproxy:setup to install it (the proxy restarts, which interrupts running sessions for a few seconds).');
}

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === 'serve') serve();
else if (cmd === 'install') await install(rest);
else if (cmd === 'uninstall') uninstall();
else if (cmd === 'status') await status();
else if (cmd === 'hook') await hook();
else if (cmd === 'setup') setup(rest);
else if (cmd === 'service') service(rest[0]);
else if (cmd === 'settings') settings(rest[0]);
else die('usage: gwproxy.mjs install --gateway-env FILE [--port N] | uninstall | status\n  steps: setup --gateway-env FILE [--port N] [--renew] | service install|uninstall | settings enable|disable | serve');
