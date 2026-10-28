import http from 'node:http';
import net from 'node:net';
import { decide } from './policy.js';

// Parse an upstream proxy URL (http:// only). Returns null when unusable.
export function parseUpstream(raw) {
  if (!raw) return null;
  let u;
  try { u = new URL(raw.includes('://') ? raw : `http://${raw}`); } catch { return null; }
  if (u.protocol !== 'http:') return { unsupported: u.protocol.replace(':', '') };
  const auth = u.username ? Buffer.from(`${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`).toString('base64') : null;
  return { host: u.hostname, port: Number(u.port || 80), auth, display: `${u.hostname}:${u.port || 80}` };
}

function splitHostPort(target, defaultPort) {
  const m = String(target).match(/^\[([^\]]+)\](?::(\d+))?$/) || String(target).match(/^([^:]+)(?::(\d+))?$/);
  if (!m) return { host: String(target), port: defaultPort };
  return { host: m[1], port: Number(m[2] || defaultPort) };
}

// Open a TCP tunnel to host:port, directly or through the upstream proxy's CONNECT.
function openTunnel(host, port, upstream, timeoutMs) {
  return new Promise((resolve, reject) => {
    const target = upstream ? { host: upstream.host, port: upstream.port } : { host, port };
    const sock = net.connect(target);
    sock.setTimeout(timeoutMs, () => sock.destroy(new Error('connect timeout')));
    sock.once('error', reject);
    sock.once('connect', () => {
      if (!upstream) { sock.setTimeout(0); resolve(sock); return; }
      const hp = host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
      sock.write(`CONNECT ${hp} HTTP/1.1\r\nHost: ${hp}\r\n${upstream.auth ? `Proxy-Authorization: Basic ${upstream.auth}\r\n` : ''}\r\n`);
      let buf = Buffer.alloc(0);
      const onData = (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        const end = buf.indexOf('\r\n\r\n');
        if (end === -1) { if (buf.length > 16384) sock.destroy(new Error('bad upstream reply')); return; }
        sock.removeListener('data', onData);
        const status = Number(buf.subarray(0, end).toString('latin1').split(' ')[1]);
        if (status !== 200) { sock.destroy(); reject(new Error(`upstream proxy answered ${status}`)); return; }
        sock.setTimeout(0);
        const rest = buf.subarray(end + 4);
        if (rest.length) sock.unshift(rest);
        resolve(sock);
      };
      sock.on('data', onData);
    });
  });
}

function denyBody(host, reason) {
  return `egress-lock blocked ${host}: ${reason}\nAllow it with: --allow ${host}\n`;
}

// Start the filtering proxy. onEvent receives one record per connection attempt.
export function startProxy({ policy, upstream = null, onEvent = () => {}, timeoutMs = 15000 }) {
  const server = http.createServer((req, res) => {
    // Plain-HTTP proxy request: absolute URI in req.url.
    let url;
    try { url = new URL(req.url); } catch {
      res.writeHead(400, { 'content-type': 'text/plain' }).end('egress-lock: this is a proxy, send absolute URLs\n');
      return;
    }
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const port = Number(url.port || 80);
    const verdict = decide(policy, host, port);
    onEvent({ kind: 'http', method: req.method, host, port, ...verdict });
    if (!verdict.allowed) {
      res.writeHead(403, { 'content-type': 'text/plain', 'x-egress-lock': 'denied' }).end(denyBody(host, verdict.reason));
      req.resume();
      return;
    }
    const headers = { ...req.headers };
    delete headers['proxy-connection'];
    delete headers['proxy-authorization'];
    const opts = upstream
      ? { host: upstream.host, port: upstream.port, path: req.url, method: req.method,
          headers: { ...headers, ...(upstream.auth ? { 'proxy-authorization': `Basic ${upstream.auth}` } : {}) } }
      : { host, port, path: `${url.pathname}${url.search}`, method: req.method, headers };
    const out = http.request(opts, (up) => {
      res.writeHead(up.statusCode || 502, up.headers);
      up.pipe(res);
    });
    out.setTimeout(timeoutMs, () => out.destroy(new Error('timeout')));
    out.on('error', (err) => {
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
      res.end(`egress-lock: upstream error: ${err.message}\n`);
    });
    req.pipe(out);
  });

  server.on('connect', async (req, clientSock, head) => {
    const { host, port } = splitHostPort(req.url, 443);
    const verdict = decide(policy, host, port);
    onEvent({ kind: 'connect', method: 'CONNECT', host, port, ...verdict });
    clientSock.on('error', () => {});
    if (!verdict.allowed) {
      const body = denyBody(host, verdict.reason);
      clientSock.end(`HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nX-Egress-Lock: denied\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
      return;
    }
    try {
      const upSock = await openTunnel(host, port, upstream, timeoutMs);
      upSock.on('error', () => clientSock.destroy());
      clientSock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) upSock.write(head);
      upSock.pipe(clientSock);
      clientSock.pipe(upSock);
    } catch (err) {
      onEvent({ kind: 'connect', method: 'CONNECT', host, port, allowed: true, reason: `allowed, but failed: ${err.message}`, failed: true });
      clientSock.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
    }
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}
