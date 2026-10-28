import fs from 'node:fs';

export const SANDBOX_EXEC = '/usr/bin/sandbox-exec';

export function sandboxAvailable() {
  return process.platform === 'darwin' && fs.existsSync(SANDBOX_EXEC);
}

// macOS Seatbelt profile: every outbound connection is denied except the egress-lock proxy
// port and the local ports the user allowed. Unix sockets stay open (most local tooling needs
// them); with blockDns the mDNSResponder socket is closed too, so names can only be resolved
// by the proxy, which closes DNS as a side channel.
export function seatbeltProfile({ proxyPort, localPorts = [], blockDns = true }) {
  const lines = [
    '(version 1)',
    '(allow default)',
    '(deny network-outbound)',
    '(allow network-outbound (remote unix-socket))',
  ];
  if (blockDns) lines.push('(deny network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))');
  for (const port of [proxyPort, ...localPorts]) {
    lines.push(`(allow network-outbound (remote ip "localhost:${Number(port)}"))`);
  }
  return lines.join('\n');
}
