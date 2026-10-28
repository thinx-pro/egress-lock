import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildPolicy, decide, parseRule } from '../src/policy.js';
import { parseUpstream, startProxy } from '../src/proxy.js';
import { summarize } from '../src/report.js';
import { sandboxAvailable, seatbeltProfile } from '../src/sandbox.js';

const BIN = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'egress-lock.js');

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

function echoServer() {
  return net.createServer((s) => s.pipe(s));
}

function viaProxyHttp(proxyPort, url) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: proxyPort, path: url, method: 'GET' }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

function viaProxyConnect(proxyPort, target, payload) {
  return new Promise((resolve, reject) => {
    const s = net.connect(proxyPort, '127.0.0.1', () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let buf = '';
    let sent = false;
    s.on('data', (d) => {
      buf += d.toString();
      if (!sent && buf.includes('\r\n\r\n')) {
        const status = Number(buf.split(' ')[1]);
        if (status !== 200) { s.destroy(); resolve({ status, data: buf }); return; }
        sent = true;
        buf = '';
        s.write(payload);
      } else if (sent && buf.length >= payload.length) {
        s.destroy();
        resolve({ status: 200, data: buf });
      }
    });
    s.on('error', reject);
  });
}

test('rules: exact host, suffix, ports', () => {
  const p = buildPolicy({ allow: ['example.com', '.corp.test', 'api.x.dev:8443'] });
  assert.equal(decide(p, 'example.com', 443).allowed, true);
  assert.equal(decide(p, 'EXAMPLE.com.', 80).allowed, true);
  assert.equal(decide(p, 'sub.example.com', 443).allowed, false);
  assert.equal(decide(p, 'corp.test', 443).allowed, true);
  assert.equal(decide(p, 'a.b.corp.test', 443).allowed, true);
  assert.equal(decide(p, 'evilcorp.test', 443).allowed, false);
  assert.equal(decide(p, 'example.com', 22).allowed, false);
  assert.equal(decide(p, 'api.x.dev', 8443).allowed, true);
  assert.equal(decide(p, 'api.x.dev', 443).allowed, false);
  assert.equal(parseRule('*.foo.io').suffix, true);
  assert.throws(() => parseRule('foo bar'));
});

test('presets and unknown presets', () => {
  const p = buildPolicy({ presets: ['npm', 'ollama'] });
  assert.equal(decide(p, 'registry.npmjs.org', 443).allowed, true);
  assert.deepEqual(p.localPorts, [11434]);
  assert.throws(() => buildPolicy({ presets: ['nope'] }), /unknown preset/);
});

test('cloud metadata is blocked even when allowed', () => {
  const p = buildPolicy({ allow: ['169.254.169.254:*', 'metadata.google.internal'] });
  assert.equal(decide(p, '169.254.169.254', 80).allowed, false);
  assert.equal(decide(p, 'metadata.google.internal', 80).allowed, false);
  assert.match(decide(p, '10.0.0.5', 443).reason, /private/);
});

test('plain HTTP: allowed host is forwarded, others get 403', async () => {
  const target = http.createServer((req, res) => res.end(`hello ${req.url}`));
  const tport = await listen(target);
  const events = [];
  const { server, port } = await startProxy({ policy: buildPolicy({ allow: [`127.0.0.1:${tport}`] }), onEvent: (e) => events.push(e) });
  try {
    const ok = await viaProxyHttp(port, `http://127.0.0.1:${tport}/x?y=1`);
    assert.equal(ok.status, 200);
    assert.equal(ok.body, 'hello /x?y=1');
    const denied = await viaProxyHttp(port, 'http://blocked.example/');
    assert.equal(denied.status, 403);
    assert.match(denied.body, /--allow blocked.example/);
    assert.deepEqual(events.map((e) => [e.host, e.allowed]), [['127.0.0.1', true], ['blocked.example', false]]);
  } finally {
    server.close();
    target.close();
  }
});

test('CONNECT: tunnel to allowed host, 403 otherwise', async () => {
  const echo = echoServer();
  const eport = await listen(echo);
  const { server, port } = await startProxy({ policy: buildPolicy({ allow: [`127.0.0.1:${eport}`] }) });
  try {
    const ok = await viaProxyConnect(port, `127.0.0.1:${eport}`, 'ping');
    assert.equal(ok.status, 200);
    assert.equal(ok.data, 'ping');
    const denied = await viaProxyConnect(port, 'exfil.example:443', 'secret');
    assert.equal(denied.status, 403);
  } finally {
    server.close();
    echo.close();
  }
});

test('allowed traffic goes through the upstream proxy', async () => {
  const echo = echoServer();
  const eport = await listen(echo);
  const upstreamEvents = [];
  const up = await startProxy({ policy: buildPolicy({ allow: [`127.0.0.1:${eport}`] }), onEvent: (e) => upstreamEvents.push(e) });
  const { server, port } = await startProxy({
    policy: buildPolicy({ allow: [`127.0.0.1:${eport}`] }),
    upstream: parseUpstream(`http://127.0.0.1:${up.port}`),
  });
  try {
    const ok = await viaProxyConnect(port, `127.0.0.1:${eport}`, 'via-upstream');
    assert.equal(ok.data, 'via-upstream');
    assert.equal(upstreamEvents.length, 1);
    assert.equal(upstreamEvents[0].kind, 'connect');
  } finally {
    server.close();
    up.server.close();
    echo.close();
  }
});

test('upstream parsing', () => {
  assert.equal(parseUpstream('http://127.0.0.1:7890').display, '127.0.0.1:7890');
  assert.equal(parseUpstream('127.0.0.1:3128').port, 3128);
  assert.ok(parseUpstream('http://u:p%40ss@proxy.local:8080').auth);
  assert.equal(parseUpstream('socks5://127.0.0.1:1080').unsupported, 'socks5');
});

test('summary groups by host and verdict', () => {
  const s = summarize([
    { host: 'a.com', port: 443, allowed: true, method: 'CONNECT' },
    { host: 'a.com', port: 443, allowed: true, method: 'CONNECT' },
    { host: 'b.cn', port: 443, allowed: false, method: 'CONNECT', reason: 'not on the allowlist' },
  ]);
  assert.equal(s.total, 3);
  assert.equal(s.allowed[0].count, 2);
  assert.equal(s.denied[0].host, 'b.cn');
});

test('seatbelt profile: proxy port and local ports only, DNS closed by default', () => {
  const prof = seatbeltProfile({ proxyPort: 4321, localPorts: [11434] });
  assert.match(prof, /\(deny network-outbound\)/);
  assert.match(prof, /localhost:4321/);
  assert.match(prof, /localhost:11434/);
  assert.match(prof, /mDNSResponder/);
  assert.doesNotMatch(prof, /localhost:\*/);
  assert.doesNotMatch(seatbeltProfile({ proxyPort: 1, blockDns: false }), /mDNSResponder/);
});

test('CLI on macOS: sandbox blocks a local port that is not allowed, allows one that is', { skip: !sandboxAvailable() }, async () => {
  const echo = echoServer();
  const allowedPort = await listen(echo);
  const other = echoServer();
  const blockedPort = await listen(other);
  const log = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'egress-lock-')), 'log.jsonl');
  const probe = (p) => `const s=require('net').connect(${p},'127.0.0.1',()=>{s.write('hi')});s.on('data',d=>{console.log('ok '+d);s.destroy()});s.on('error',e=>{console.log('err '+e.code)})`;
  try {
    const run = (p) => new Promise((resolve) => {
      // spawnSync would block the event loop that serves the echo servers; use a child and wait.
      import('node:child_process').then(({ spawn }) => {
        const c = spawn(process.execPath, [BIN, '--allow-local', String(allowedPort), '--no-upstream', '-q', '--log', log, '--', process.execPath, '-e', probe(p)]);
        let out = '';
        c.stdout.on('data', (d) => { out += d; });
        c.on('exit', () => resolve(out.trim()));
      });
    });
    assert.equal(await run(allowedPort), 'ok hi');
    assert.match(await run(blockedPort), /^err E(PERM|ACCES|CONNREFUSED)/);
  } finally {
    echo.close();
    other.close();
  }
});

test('CLI usage errors exit 2', () => {
  const r = spawnSync(process.execPath, [BIN, '--allow', 'x.com'], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /nothing to run/);
  const h = spawnSync(process.execPath, [BIN, '--help'], { encoding: 'utf8' });
  assert.equal(h.status, 0);
  assert.match(h.stdout, /--allow-local/);
});
