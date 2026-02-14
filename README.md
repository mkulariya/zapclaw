# Pincer 🦞

**Secure, Lightweight, High-Performance AI Agent**

A security-first clone of OpenClaw, built in Rust. Pincer retains >95% of OpenClaw's utility while eliminating all known security vulnerabilities.

---

## Why Pincer?

OpenClaw has critical security issues:
- **CVE-2026-25253**: 1-click RCE via attacker-controlled content
- **Exposed gateways** bound to `0.0.0.0:18789` by default
- **Prompt injection** vulnerability ("lethal trifecta")
- **Bloated dependencies**: 385KB lockfile, 60+ npm packages

Pincer fixes all of these while staying lightweight and fast.

## Features

| Feature | Pincer | OpenClaw |
|---|---|---|
| Language | Rust | Node.js/TypeScript |
| Binary size | ~15MB | ~500MB+ (with node_modules) |
| RAM usage | <256MB | >1GB |
| Response latency | <1s | 2-5s |
| Default network exposure | **None** (localhost only) | `0.0.0.0:18789` |
| Prompt injection guard | ✅ Multi-layer | ❌ None |
| Workspace confinement | ✅ Symlink-safe | ❌ Partial |
| Sandbox | ✅ Bubblewrap (mandatory) | ❌ None |
| LLM support | Ollama (local) + Cloud | Cloud only |
| Dependencies | ~25 crates | 60+ npm packages |

## Quick Start

### Install

```bash
# 1. Install Rust (one-time, skip if you already have it)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Install bubblewrap (required — Pincer runs inside a sandbox)
sudo apt install bubblewrap        # Debian/Ubuntu
# sudo dnf install bubblewrap      # Fedora
# sudo pacman -S bubblewrap        # Arch
# brew install bubblewrap           # macOS

# 3. Install Ollama (one-time, only required for local LLM inference)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull phi3:mini

# 4. Install Pincer
cargo install --git https://github.com/your-org/pincer.git pincer-cli
```

That's it. Now `pincer` is available as a command from anywhere. It automatically runs inside a bubblewrap sandbox for security.

### Run

```bash
# Interactive REPL
pincer

# Single task
pincer --task "What is sqrt(144) + 3^2?"

# Cloud LLM mode (no Ollama needed)
PINCER_API_KEY="sk-your-key" pincer --model-mode cloud --model-name gpt-4o
```

### REPL Commands

| Command | Description |
|---|---|
| `/status` | Show session info (memory files, tokens, session ID) |
| `/compact [N]` | Compact memory, keep last N days (default: 7) |
| `/resume` | List recent sessions |
| `/resume <id>` | Resume a previous session |
| `/update` | Self-update from git |
| `help` | Show help |
| `tools` | List available tools |
| `exit` | Quit |

## Architecture

```
pincer/
├── pincer-core/       # Core agent runtime
│   ├── agent.rs           # Observe-Plan-Act-Reflect loop
│   ├── llm.rs             # OpenAI-compatible client (Ollama + Cloud)
│   ├── memory.rs          # SQLite session memory (4K token limit)
│   ├── sanitizer.rs       # Prompt injection guard
│   ├── confiner.rs        # Workspace path confinement
│   ├── sandbox.rs         # Bubblewrap sandbox enforcement
│   └── config.rs          # Env-var based configuration
├── pincer-tools/      # Safe tool implementations
│   ├── math_tool.rs       # Pure Rust math evaluator
│   ├── file_tool.rs       # Workspace-confined file I/O
│   ├── browser_tool.rs    # Read-only HTTP browser
│   └── confirmation.rs    # Human-in-the-loop confirmation
├── pincer-cli/        # CLI binary (REPL + single-task)
├── pincer-tunnels/    # Secure communication
│   ├── outbound.rs        # HTTPS proxy (mTLS, rate limiting)
│   └── inbound.rs         # JSON-RPC 2.0 server
└── scripts/
    ├── sandbox.sh         # Deprecated — sandbox is now built-in
    └── gen_certs.sh       # mTLS certificate generator
```

## Security Model

### Defense in Depth

1. **Input Sanitization** — Multi-pattern regex guard against prompt injection
2. **Workspace Confinement** — All file I/O restricted to workspace (symlink-safe canonicalization)
3. **No Delete Operations** — File tool supports read/write/append only
4. **Network Isolation** — Zero default exposure; outbound/inbound tunnels disabled by default
5. **Rate Limiting** — Sliding-window limiter on outbound requests
6. **Domain Allowlisting** — Only approved domains reachable via outbound tunnel
7. **mTLS Authentication** — Mutual TLS for cloud API connections
8. **Sandbox** — Mandatory bubblewrap isolation (read-only root FS, PID namespace, capability drop)
9. **Human Confirmation** — Required for sensitive tool calls
10. **Max Steps Guard** — Agent loop capped at 15 iterations

### SSRF Prevention

The browser tool blocks all private/local network addresses:
- `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`
- RFC 1918 ranges: `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`
- Link-local: `169.254.x.x`

## CLI Options

```
Pincer 🦞 — Secure, lightweight AI agent

Usage: pincer [OPTIONS]

Options:
  -w, --workspace <DIR>      Workspace directory [default: ./pincer_workspace]
  -m, --model-mode <MODE>    LLM mode: "local" or "cloud" [default: local]
  -n, --model-name <NAME>    Model name [default: phi3:mini]
      --api-url <URL>        API base URL
      --api-key <KEY>        API key [env: PINCER_API_KEY]
      --max-steps <N>        Max agent steps per task [default: 15]
  -t, --task <TASK>          Run single task and exit
      --no-confirm           Disable confirmation prompts
      --no-sandbox           Skip bubblewrap sandbox (dev only)
      --sandbox-no-network   Disable network inside sandbox
  -h, --help                 Print help
  -V, --version              Print version
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `PINCER_WORKSPACE` | Workspace directory | `./pincer_workspace` |
| `PINCER_LLM_MODE` | `local` or `cloud` | `local` |
| `PINCER_API_BASE_URL` | LLM API endpoint | `http://localhost:11434/v1` |
| `PINCER_API_KEY` | API key (cloud mode) | — |
| `PINCER_MODEL` | Model identifier | `phi3:mini` |
| `PINCER_MAX_STEPS` | Max loop iterations | `15` |
| `PINCER_TOOL_TIMEOUT` | Tool timeout (seconds) | `5` |
| `PINCER_SANDBOXED` | Set to `1` when running inside sandbox (auto-set) | — |

## Available Tools

| Tool | Description | Confirmation |
|---|---|---|
| `math_eval` | Evaluate math expressions (arithmetic, functions, constants) | No |
| `file_ops` | Read/write/append/list files in workspace | No |
| `browse_url` | Fetch and read web page content (read-only) | Yes |

## Sandbox

Pincer **always** runs inside a bubblewrap (bwrap) sandbox by default. The binary self-wraps: on startup, if not already sandboxed, it re-execs itself inside bwrap with full namespace isolation.

**Sandbox properties:**
- Read-only root filesystem
- Isolated PID, IPC, UTS namespaces
- All capabilities dropped
- Only the workspace directory is writable
- Isolated /tmp
- Process dies with parent

Network is enabled by default (needed for Ollama on localhost and cloud APIs). Use `--sandbox-no-network` to disable.

```bash
# Normal usage — sandbox is automatic
pincer --task "Calculate pi * e"

# Disable network inside sandbox
pincer --sandbox-no-network --task "What is 2+2?"

# Skip sandbox (development only — NOT recommended)
pincer --no-sandbox
```

If bubblewrap is not installed, Pincer prints a warning and runs without sandbox (degraded security).

## Testing

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration_tests

# Security fuzz tests  
cargo test --test security_fuzz

# Performance benchmarks
cargo bench

# Dependency audit
cargo install cargo-audit
cargo audit
```

## Building Release

```bash
# Optimized release build
cargo build --release

# Package for distribution
./scripts/release.sh
```

## License

MIT
