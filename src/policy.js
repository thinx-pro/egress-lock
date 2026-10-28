import net from 'node:net';
import { PRESETS } from './presets.js';

// Cloud instance metadata endpoints hand out credentials. Never reachable, even if allowed.
const METADATA = new Set([
  '169.254.169.254', 'fd00:ec2::254', 'metadata.google.internal', 'metadata.goog',
  '100.100.100.200', 'metadata.azure.com', '169.254.170.2',
]);
const DEFAULT_PORTS = new Set([80, 443]);

export function normalizeHost(host) {
  let h = String(host || '').trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  while (h.endsWith('.')) h = h.slice(0, -1);
  return h;
}

// A rule is "host", ".host" / "*.host" (domain + subdomains), optionally ":port" (or ":*").
export function parseRule(raw) {
  let s = String(raw).trim().toLowerCase();
  if (!s) throw new Error('empty allow rule');
  let port = null;
  const m = s.match(/^(\[[^\]]+\]|[^:]+):(\d+|\*)$/);
  if (m) {
    s = m[1];
    port = m[2] === '*' ? '*' : Number(m[2]);
  }
  let suffix = false;
  if (s.startsWith('*.')) { suffix = true; s = s.slice(2); } else if (s.startsWith('.')) { suffix = true; s = s.slice(1); }
  const host = normalizeHost(s);
  if (!host || /[\s/]/.test(host)) throw new Error(`invalid allow rule: ${raw}`);
  return { raw: String(raw), host, suffix, port };
}

export function buildPolicy({ allow = [], presets = [], localPorts = [] } = {}) {
  const rules = [];
  const ports = new Set(localPorts.map(Number));
  for (const name of presets) {
    const p = PRESETS[name];
    if (!p) throw new Error(`unknown preset: ${name} (see: egress-lock presets)`);
    for (const h of p.hosts || []) rules.push(parseRule(h));
    for (const port of p.localPorts || []) ports.add(port);
  }
  for (const r of allow) rules.push(parseRule(r));
  return { rules, localPorts: [...ports].filter(Number.isInteger).sort((a, b) => a - b) };
}

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const v = ip.toLowerCase();
  return v === '::1' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80') || v === '::';
}

// Decide one connection attempt. Returns { allowed, reason, rule }.
export function decide(policy, hostIn, portIn) {
  const host = normalizeHost(hostIn);
  const port = Number(portIn);
  if (!host) return { allowed: false, reason: 'no host' };
  if (METADATA.has(host)) return { allowed: false, reason: 'cloud metadata endpoint (always blocked)' };
  for (const rule of policy.rules) {
    const hostOk = rule.suffix ? host === rule.host || host.endsWith(`.${rule.host}`) : host === rule.host;
    if (!hostOk) continue;
    const portOk = rule.port === '*' || (rule.port === null ? DEFAULT_PORTS.has(port) : rule.port === port);
    if (portOk) return { allowed: true, reason: 'allowlist', rule: rule.raw };
    return { allowed: false, reason: `port ${port} not allowed for ${rule.raw} (add ${host}:${port})` };
  }
  if (net.isIP(host)) {
    return { allowed: false, reason: isPrivateIp(host) ? 'private/local IP not on the allowlist' : 'IP address not on the allowlist' };
  }
  return { allowed: false, reason: 'not on the allowlist' };
}
