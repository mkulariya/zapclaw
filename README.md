# ZapClaw 🦞

**Secure, Lightweight, High-Performance AI Agent**

A security-first clone of OpenClaw, built in Rust. ZapClaw retains >95% of OpenClaw's utility while eliminating all known security vulnerabilities.

---

## Why ZapClaw?

OpenClaw has critical security issues:
- **CVE-2026-25253**: 1-click RCE via attacker-controlled content
- **Exposed gateways** bound to `0.0.0.0:18789` by default
- **Prompt injection** vulnerability ("lethal trifecta")
- **Bloated dependencies**: 385KB lockfile, 60+ npm packages

ZapClaw fixes all of these while staying lightweight and fast.

## Features

| Feature | ZapClaw | OpenClaw |
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

# 2. Install bubblewrap (required — ZapClaw runs inside a sandbox)
sudo apt install bubblewrap        # Debian/Ubuntu
# sudo dnf install bubblewrap      # Fedora
# sudo pacman -S bubblewrap        # Arch
# brew install bubblewrap           # macOS

# 3. Install Ollama (one-time, only required for local LLM inference)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull phi3:mini

# 4. Install ZapClaw
cargo install --git https://github.com/your-org/zapclaw.git zapclaw-cli
```

That's it. Now `zapclaw` is available as a command from anywhere. It automatically runs inside a bubblewrap sandbox for security.

### Run

```bash
# Interactive REPL (requires explicit endpoint configuration)
zapclaw --api-url http://localhost:11434/v1 --model-name phi3:mini

# Single task
zapclaw --api-url http://localhost:11434/v1 --model-name phi3:mini --task "What is sqrt(144) + 3^2?"

# Using environment variables
export ZAPCLAW_API_BASE_URL="http://localhost:11434/v1"
export ZAPCLAW_MODEL="phi3:mini"
zapclaw

# Cloud LLM (e.g., OpenAI)
export ZAPCLAW_API_BASE_URL="https://api.openai.com/v1"
export ZAPCLAW_API_KEY="sk-your-key"
export ZAPCLAW_MODEL="gpt-4o"
zapclaw
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
zapclaw/
├── zapclaw-core/       # Core agent runtime
│   ├── agent.rs           # Observe-Plan-Act-Reflect loop
│   ├── llm.rs             # OpenAI-compatible client (Ollama + Cloud)
│   ├── memory.rs          # SQLite session memory (4K token limit)
│   ├── sanitizer.rs       # Prompt injection guard
│   ├── confiner.rs        # Workspace path confinement
│   ├── sandbox.rs         # Bubblewrap sandbox enforcement
│   └── config.rs          # Env-var based configuration
├── zapclaw-tools/      # Safe tool implementations
│   ├── math_tool.rs       # Pure Rust math evaluator
│   ├── file_tool.rs       # Workspace-confined file I/O
│   ├── browser_tool.rs    # Read-only HTTP browser
│   └── confirmation.rs    # Human-in-the-loop confirmation
├── zapclaw-cli/        # CLI binary (REPL + single-task)
├── zapclaw-tunnels/    # Secure communication
│   ├── outbound.rs        # HTTPS proxy (mTLS, rate limiting)
│   └── inbound.rs         # JSON-RPC 2.0 server
└── scripts/
    ├── zapclaw-remote.sh   # Remote client (SSH tunnel + JSON-RPC)
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
ZapClaw 🦞 — Secure, lightweight AI agent

Usage: zapclaw [OPTIONS]

Options:
  -w, --workspace <DIR>      Workspace directory [default: ./zapclaw_workspace]
  -n, --model-name <NAME>    Model name [env: ZAPCLAW_MODEL] (required)
      --api-url <URL>        API base URL [env: ZAPCLAW_API_BASE_URL] (required)
      --api-key <KEY>        API key [env: ZAPCLAW_API_KEY] (required for remote endpoints)
      --max-steps <N>        Max agent steps per task [default: 15]
  -t, --task <TASK>          Run single task and exit
      --no-confirm           Disable confirmation prompts
      --no-sandbox           Skip bubblewrap sandbox (dev only)
      --sandbox-no-network   Disable network inside sandbox
      --enable-inbound       Enable remote JSON-RPC server
      --inbound-port <PORT>  Inbound server port [default: 9876]
      --inbound-bind <ADDR>  Bind address [default: 127.0.0.1]
      --inbound-api-key <KEY> API key for remote auth [env: ZAPCLAW_INBOUND_KEY]
  -h, --help                 Print help
  -V, --version              Print version
```

**Important:** ZapClaw requires explicit endpoint configuration. You must specify:
- `--api-url` (or `ZAPCLAW_API_BASE_URL` env var): The LLM API endpoint
- `--model-name` (or `ZAPCLAW_MODEL` env var): The model identifier
- `--api-key` (or `ZAPCLAW_API_KEY` env var): Required only for non-localhost endpoints

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `ZAPCLAW_WORKSPACE` | Workspace directory | `./zapclaw_workspace` |
| `ZAPCLAW_API_BASE_URL` | LLM API endpoint (required) | — |
| `ZAPCLAW_MODEL` | Model identifier (required) | — |
| `ZAPCLAW_API_KEY` | API key (required for remote endpoints) | — |
| `ZAPCLAW_MAX_STEPS` | Max loop iterations | `15` |
| `ZAPCLAW_TOOL_TIMEOUT` | Tool timeout (seconds) | `5` |
| `ZAPCLAW_SANDBOXED` | Set to `1` when running inside sandbox (auto-set) | — |
| `ZAPCLAW_INBOUND_KEY` | API key for remote inbound tunnel | — |

**Note:** API key is optional only for loopback endpoints (localhost, 127.0.0.1, ::1). All other endpoints require an API key.

## Available Tools

| Tool | Description | Confirmation |
|---|---|---|
| `math_eval` | Evaluate math expressions (arithmetic, functions, constants) | No |
| `file_ops` | Read/write/append/list files in workspace | No |
| `browse_url` | Fetch and read web page content (read-only) | Yes |

## Sandbox

ZapClaw **always** runs inside a bubblewrap (bwrap) sandbox by default. The binary self-wraps: on startup, if not already sandboxed, it re-execs itself inside bwrap with full namespace isolation.

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
zapclaw --task "Calculate pi * e"

# Disable network inside sandbox
zapclaw --sandbox-no-network --task "What is 2+2?"

# Skip sandbox (development only — NOT recommended)
zapclaw --no-sandbox
```

## Remote Access

ZapClaw can be accessed remotely from any machine (laptop, phone, tablet) over SSH. The inbound server is disabled by default and must be explicitly enabled.

### 1. Start the Server

On the machine running ZapClaw:

```bash
# Generate a secure API key
export ZAPCLAW_KEY="$(openssl rand -hex 16)"
echo "Your API key: $ZAPCLAW_KEY"

# Start ZapClaw with remote access
zapclaw --enable-inbound --inbound-api-key "$ZAPCLAW_KEY"
```

### 2. Connect from Another Machine

On your laptop, phone (Termux), or any machine with SSH:

```bash
# Open SSH tunnel to the server
ssh -L 9876:localhost:9876 user@my-server

# Set up the client
export ZAPCLAW_REMOTE_HOST="user@my-server"
export ZAPCLAW_REMOTE_KEY="<your-key>"
```

### 3. Use ZapClaw Remotely

```bash
# Interactive terminal (multi-turn conversation)
./scripts/zapclaw-remote.sh -i

# One-shot task
./scripts/zapclaw-remote.sh "What files changed today?"

# File transfer
./scripts/zapclaw-remote.sh --upload data.csv
./scripts/zapclaw-remote.sh --download results.txt
./scripts/zapclaw-remote.sh --list .csv

# Health check
./scripts/zapclaw-remote.sh --health
```

### Security

- Server binds to `127.0.0.1` only — never exposed to the network directly
- API key required on every request
- All inbound tasks pass through the input sanitizer
- File operations confined to workspace via Confiner
- Transport encrypted via SSH tunnel
- Agent still runs inside bubblewrap sandbox

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
