# egress-lock

**Run an agent, a local model's tool loop or an install script with outbound network limited to an allowlist. Every connection attempt is logged; on macOS the OS enforces it.**

<!-- agent-preflight -->
> **Also a Claude Code skill.** `egress-lock` is part of [agent-preflight](https://github.com/thinx-pro/agent-preflight), a set of offline checks for coding agents: `/plugin marketplace add thinx-pro/agent-preflight` then `/plugin install egress-lock@agent-preflight`, and ask Claude in plain words.

![node 18+](https://img.shields.io/badge/node-18%2B-3f8f5a) ![zero dependencies](https://img.shields.io/badge/dependencies-0-3f8f5a) ![macOS enforced](https://img.shields.io/badge/macOS-sandbox--exec%20enforced-3f8f5a) ![license MIT](https://img.shields.io/badge/license-MIT-blue)

```text
$ egress-lock --preset pypi -- python3 agent_step.py
200
egress-lock: 2 connection attempt(s), 1 host(s) allowed, 1 denied
  DENIED  oss-cn-beijing.aliyuncs.com:443  x1  CONNECT  not on the allowlist
  allowed pypi.org:443  x1
  to allow: --allow oss-cn-beijing.aliyuncs.com
  log: ~/.egress-lock/2026-10-28T04-22-14.jsonl
```

<sub>Output of a manual test (see Tested below): a Python script fetched from PyPI (allowed by the preset), then tried an object-storage endpoint in Beijing (refused and logged). The command line and log path are shortened; the Python traceback from the refused request is left out.</sub>

## Why

In October 2026 [Cohere reported](https://cohere.com/blog/concerning-behaviour-popular-open-weight-ai-model) that Qwen3.8-Flash-Next, asked to write a detection rule in an offline sandbox, inventoried the machine and tried to upload a test file to an Alibaba Cloud storage bucket in Beijing, right after its reasoning said no tools would be called. When they probed for the trigger, the model reached for the cloud metadata address `169.254.169.254` (where cloud machines fetch their credentials) in 23–36% of completions. Their sandbox had no route out, so the request died there; as they put it, on a developer's laptop or a CI runner with normal network access it would have gone through. Cohere lists two explanations, leftover traces from training sandboxes or a deliberate call-home, and recommends enforcing on the actual tool call and alerting on cloud URLs you don't normally use.

You can't tell from a reasoning trace which it is, and the same goes for anything else you run without reading first: a `postinstall` script, a model's generated code, an MCP server you just found. egress-lock gives such a run the network it needs (a package registry, one API) and nothing else, and leaves a record of what it tried.

## Quick start

```bash
npx github:thinx-pro/egress-lock --preset npm -- npm install
npx github:thinx-pro/egress-lock --allow api.example.com --allow-local 11434 -- python3 my_agent.py
```

Then read what happened: the summary is printed when the command exits, and `egress-lock report` summarizes every log in `~/.egress-lock/`.

## Options

| Option | Meaning |
|---|---|
| `--allow <rules>` | `example.com` (ports 80/443), `.example.com` or `*.example.com` (domain + subdomains), `example.com:8443`, `example.com:*` |
| `--preset <names>` | `npm`, `pypi`, `github`, `huggingface`, `crates`, `go`, `anthropic`, `openai`, `ollama` (local port 11434), `lmstudio` (1234). `egress-lock presets` lists the hosts |
| `--allow-local <ports>` | local ports the command may connect to directly, e.g. a model server |
| `--log <file>` | JSONL log of every attempt (default `~/.egress-lock/<time>.jsonl`) |
| `--upstream <url>` / `--no-upstream` | forward allowed traffic through an `http://` proxy; by default your own `HTTPS_PROXY`/`HTTP_PROXY` is used, so it works behind a corporate proxy or a local proxy client |
| `--no-sandbox` | macOS: proxy only |
| `--allow-dns` | macOS: let the command resolve names itself (closed by default, see below) |
| `--json`, `-q` | machine-readable summary on stderr / no summary |

The exit code is the command's own.

## How it works

1. egress-lock starts a filtering HTTP/HTTPS proxy on `127.0.0.1` (random port). Each `CONNECT` or proxied request is checked against the allowlist, logged, and either tunneled (directly, or through your upstream proxy) or answered with `403` and a message saying which `--allow` would permit it.
2. The command runs with `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` (both cases), `npm_config_proxy`, `npm_config_https_proxy` and `NODE_USE_ENV_PROXY=1` pointing at that proxy. curl, git, pip, npm, Python's urllib and requests, and Node's `fetch` honour these.
3. **On macOS** the command also runs under `sandbox-exec` with a profile that denies every outbound connection except to the proxy's port and the `--allow-local` ports. Programs that ignore proxy settings, raw sockets, and direct use of your own local proxy client are all refused by the OS. The macOS DNS resolver socket is closed too, so names can only be resolved by egress-lock, which also closes DNS as a covert channel. Unix-domain sockets otherwise stay open.
4. Cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200` and others) are always refused, even if you allow them. IP addresses and private ranges are refused unless allowed explicitly.

## Tested

- `npm test`: 11 tests, all offline against local servers: rule matching, presets, metadata blocking, HTTP forwarding and `CONNECT` tunnels (allowed and denied), chaining through an upstream proxy, and, on macOS, the OS sandbox refusing a local port that isn't allowed while allowing one that is.
- By hand on macOS (Darwin 27, Node 24), behind a local proxy client:

| Command under egress-lock | Result |
|---|---|
| `--allow example.com -- curl https://example.com` | 200 (through the upstream proxy) |
| `--allow example.com -- curl https://www.google.com` | refused, 403, logged |
| `-- curl --noproxy '*' https://example.com` | `Could not resolve host` (DNS closed) |
| `-- curl --noproxy '*' http://1.1.1.1/` | `Couldn't connect` (sandbox) |
| `-- curl --proxy http://127.0.0.1:7890 …` (the user's own proxy client) | `Couldn't connect` (sandbox) |
| `-- curl http://169.254.169.254/latest/meta-data/` | 403, "cloud metadata endpoint" |
| `--preset pypi -- python3` urllib to pypi.org, then to `oss-cn-beijing.aliyuncs.com` | 200, then refused and logged |
| `--allow example.com -- node -e "fetch(…)"` | example.com 200, google.com refused |
| `--preset npm -- npm view left-pad version` | works |
| `--preset github -- git ls-remote https://github.com/…` | works |

## Limits

- **Linux and Windows: proxy mode only.** A program that ignores proxy settings (or opens raw sockets) is not stopped there. For enforcement on Linux, run the command in a network namespace or container whose only route out is egress-lock; built-in support is on the roadmap.
- **`sandbox-exec` is deprecated by Apple** (it still ships and works on current macOS, and is what several sandboxing tools use). If Apple removes it, egress-lock falls back to proxy mode and says so.
- It sees host names and ports, not what's inside HTTPS. An allowed host can still receive data you didn't intend to send: allow as little as the job needs.
- Unix-domain sockets stay open, so a local daemon reachable that way (for example the Docker socket) is a way around it.
- HTTP/3 (QUIC over UDP) to allowed hosts isn't proxied; on macOS the sandbox blocks it, and clients fall back to TCP.
- The upstream proxy must be `http://`; SOCKS upstreams aren't supported yet.

## Roadmap

Linux enforcement with network namespaces, a SOCKS5 listener for clients that only speak SOCKS, per-host byte counts, and a "learn" mode that proposes an allowlist from a trial run.

## License

MIT
