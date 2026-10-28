// Group connection events by host and verdict.
export function summarize(events) {
  const byHost = new Map();
  for (const e of events) {
    const key = `${e.allowed ? 'allowed' : 'denied'}\t${e.host}:${e.port}`;
    const cur = byHost.get(key) || { host: e.host, port: e.port, allowed: e.allowed, count: 0, reason: e.reason, methods: new Set(), failed: 0 };
    cur.count += 1;
    if (e.method) cur.methods.add(e.method);
    if (e.failed) cur.failed += 1;
    byHost.set(key, cur);
  }
  const rows = [...byHost.values()].sort((a, b) => Number(a.allowed) - Number(b.allowed) || b.count - a.count || a.host.localeCompare(b.host));
  return {
    allowed: rows.filter((r) => r.allowed),
    denied: rows.filter((r) => !r.allowed),
    total: events.length,
  };
}

export function renderSummary(sum, { color = false, logPath } = {}) {
  const red = (s) => (color ? `\x1b[31m${s}\x1b[0m` : s);
  const green = (s) => (color ? `\x1b[32m${s}\x1b[0m` : s);
  const dim = (s) => (color ? `\x1b[2m${s}\x1b[0m` : s);
  const out = [];
  out.push(`egress-lock: ${sum.total} connection attempt(s), ${sum.allowed.length} host(s) allowed, ${sum.denied.length} denied`);
  for (const r of sum.denied) {
    out.push(`  ${red('DENIED ')} ${r.host}:${r.port}  x${r.count}  ${[...r.methods].join(',')}  ${dim(r.reason)}`);
  }
  for (const r of sum.allowed) {
    out.push(`  ${green('allowed')} ${r.host}:${r.port}  x${r.count}${r.failed ? `  (${r.failed} failed)` : ''}`);
  }
  if (sum.denied.length) {
    const hosts = [...new Set(sum.denied.filter((r) => !/metadata/.test(r.reason)).map((r) => r.host))];
    if (hosts.length) out.push(dim(`  to allow: --allow ${hosts.join(',')}`));
  }
  if (logPath) out.push(dim(`  log: ${logPath}`));
  return out.join('\n');
}
