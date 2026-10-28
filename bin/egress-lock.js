#!/usr/bin/env node
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildPolicy } from '../src/policy.js';
import { PRESETS } from '../src/presets.js';
import { parseUpstream, startProxy } from '../src/proxy.js';
import { renderSummary, summarize } from '../src/report.js';
import { SANDBOX_EXEC, sandboxAvailable, seatbeltProfile } from '../src/sandbox.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(fs.readFileSync(path.join(here, '..', 'package.json'), 'utf8')).version;

const HELP = `egress-lock ${VERSION}
Run a command with outbound network access limited to an allowlist, and log every attempt.

Usage
  egress-lock [options] -- <command> [args...]
  egress-lock report [log.jsonl ...]      summarize earlier runs
  egress-lock presets                     list named allowlists

Options
  --allow <rules>       hosts to allow, comma-separated or repeated:
                          example.com        that host, ports 80/443
                          .example.com       the domain and all subdomains (same as *.example.com)
                          example.com:8443   a specific port (example.com:* for any)
  --preset <names>      named allowlists: ${Object.keys(PRESETS).join(', ')}
  --allow-local <ports> local ports the command may reach directly (e.g. 11434 for Ollama)
  --log <file>          append JSONL events here (default: ~/.egress-lock/<time>.jsonl)
  --upstream <url>      forward allowed traffic through this http:// proxy
                        (default: your HTTPS_PROXY / HTTP_PROXY, if set)
  --no-upstream         ignore HTTPS_PROXY / HTTP_PROXY and connect directly
  --no-sandbox          macOS: proxy only, don't enforce with sandbox-exec
  --allow-dns           macOS: let the command resolve DNS itself (closed by default)
  --json                print the summary as JSON on stderr
  -q, --quiet           no summary
  -h, --help | -v, --version

How it works
  The command gets HTTP(S)_PROXY pointing at a local filtering proxy. On macOS it also runs
  under sandbox-exec, which blocks every other outbound connection, so programs that ignore
  proxy settings can't get around it. On Linux and Windows only the proxy applies.
  Cloud metadata addresses (169.254.169.254 and friends) are always blocked.

Exit code: the command's own exit code (2 for egress-lock usage errors).
`;

function fail(msg) {
  process.stderr.write(`egress-lock: ${msg}\n`);
  process.exit(2);
}

function list(v) {
  return String(v).split(',').map((s) => s.trim()).filter(Boolean);
}

function parseArgs(argv) {
  const o = { allow: [], presets: [], localPorts: [], log: null, upstream: undefined, sandbox: true,
    allowDns: false, json: false, quiet: false, cmd: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { if (i + 1 >= argv.length) fail(`${a} needs a value`); return argv[++i]; };
    if (a === '--') { o.cmd = argv.slice(i + 1); break; }
    else if (a === '--allow') o.allow.push(...list(val()));
    else if (a === '--preset') o.presets.push(...list(val()));
    else if (a === '--allow-local') o.localPorts.push(...list(val()).map(Number));
    else if (a === '--log') o.log = val();
    else if (a === '--upstream') o.upstream = val();
    else if (a === '--no-upstream') o.upstream = null;
    else if (a === '--no-sandbox') o.sandbox = false;
    else if (a === '--allow-dns') o.allowDns = true;
    else if (a === '--json') o.json = true;
    else if (a === '-q' || a === '--quiet') o.quiet = true;
    else if (a === '-h' || a === '--help') { process.stdout.write(HELP); process.exit(0); }
    else if (a === '-v' || a === '--version') { process.stdout.write(`${VERSION}\n`); process.exit(0); }
    else fail(`unknown option ${a} (see --help)`);
  }
  if (o.localPorts.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) fail('--allow-local takes port numbers');
  return o;
}

function readEvents(files) {
  const events = [];
  for (const f of files) {
    for (const line of fs.readFileSync(f, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try { events.push(JSON.parse(line)); } catch { /* skip torn line */ }
    }
  }
  return events;
}

function defaultLogPath() {
  const dir = path.join(os.homedir(), '.egress-lock');
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  return path.join(dir, `${stamp}.jsonl`);
}

async function run(o) {
  if (!o.cmd.length) fail('nothing to run: egress-lock [options] -- <command> (see --help)');
  let policy;
  try { policy = buildPolicy({ allow: o.allow, presets: o.presets, localPorts: o.localPorts }); } catch (e) { fail(e.message); }

  const envProxy = process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy;
  let upstream = null;
  const upRaw = o.upstream === undefined ? envProxy : o.upstream;
  if (upRaw) {
    upstream = parseUpstream(upRaw);
    if (!upstream) fail(`can't parse upstream proxy ${upRaw}`);
    if (upstream.unsupported) {
      process.stderr.write(`egress-lock: upstream ${upstream.unsupported} proxy not supported, connecting directly\n`);
      upstream = null;
    }
  }

  const logPath = o.log || defaultLogPath();
  fs.mkdirSync(path.dirname(path.resolve(logPath)), { recursive: true });
  const logFd = fs.openSync(logPath, 'a');
  const events = [];
  const onEvent = (e) => {
    const rec = { ts: new Date().toISOString(), ...e };
    events.push(rec);
    fs.writeSync(logFd, `${JSON.stringify(rec)}\n`);
  };

  const { server, port } = await startProxy({ policy, upstream, onEvent });
  const proxyUrl = `http://127.0.0.1:${port}`;
  const noProxy = 'localhost,127.0.0.1,::1';
  const env = {
    ...process.env,
    HTTP_PROXY: proxyUrl, HTTPS_PROXY: proxyUrl, ALL_PROXY: proxyUrl,
    http_proxy: proxyUrl, https_proxy: proxyUrl, all_proxy: proxyUrl,
    NO_PROXY: noProxy, no_proxy: noProxy,
    npm_config_proxy: proxyUrl, npm_config_https_proxy: proxyUrl,
    NODE_USE_ENV_PROXY: '1',
    EGRESS_LOCK: '1',
  };

  const enforce = o.sandbox && sandboxAvailable();
  let file = o.cmd[0];
  let args = o.cmd.slice(1);
  if (enforce) {
    const profile = seatbeltProfile({ proxyPort: port, localPorts: policy.localPorts, blockDns: !o.allowDns });
    args = ['-p', profile, file, ...args];
    file = SANDBOX_EXEC;
  } else if (!o.quiet) {
    const why = o.sandbox ? `no OS enforcement on ${process.platform}` : '--no-sandbox';
    process.stderr.write(`egress-lock: proxy mode only (${why}): programs that ignore proxy settings are not blocked\n`);
  }

  const child = spawn(file, args, { stdio: 'inherit', env });
  const forward = (sig) => { try { child.kill(sig); } catch { /* gone */ } };
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(sig, () => forward(sig));

  const code = await new Promise((resolve) => {
    child.on('error', (err) => { process.stderr.write(`egress-lock: cannot run ${o.cmd[0]}: ${err.message}\n`); resolve(127); });
    child.on('exit', (c, sig) => resolve(c ?? (sig ? 128 + (os.constants.signals[sig] || 0) : 1)));
  });
  server.close();
  fs.closeSync(logFd);

  const sum = summarize(events);
  if (o.json) {
    process.stderr.write(`${JSON.stringify({ exitCode: code, enforced: enforce, log: logPath, ...sum }, (k, v) => (v instanceof Set ? [...v] : v))}\n`);
  } else if (!o.quiet) {
    process.stderr.write(`${renderSummary(sum, { color: process.stderr.isTTY && !process.env.NO_COLOR, logPath })}\n`);
  }
  return code;
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === 'presets') {
    for (const [name, p] of Object.entries(PRESETS)) {
      const what = [...(p.hosts || []), ...(p.localPorts || []).map((x) => `localhost:${x}`)].join(', ');
      process.stdout.write(`${name.padEnd(12)} ${p.about}\n${' '.repeat(13)}${what}\n`);
    }
    return 0;
  }
  if (argv[0] === 'report') {
    let files = argv.slice(1);
    if (!files.length) {
      const dir = path.join(os.homedir(), '.egress-lock');
      files = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.jsonl')).sort().map((f) => path.join(dir, f)) : [];
      if (!files.length) fail('no logs found in ~/.egress-lock');
    }
    process.stdout.write(`${renderSummary(summarize(readEvents(files)), { color: process.stdout.isTTY && !process.env.NO_COLOR })}\n`);
    return 0;
  }
  return run(parseArgs(argv));
}

main().then((code) => process.exit(code), (err) => fail(err.stack || String(err)));
