# SafePincer 🦞

**Secure, Lightweight, High-Performance AI Agent**

A security-first clone of OpenClaw, built in Rust. SafePincer retains >95% of OpenClaw's utility while eliminating all known security vulnerabilities.

---

## Why SafePincer?

OpenClaw has critical security issues:
- **CVE-2026-25253**: 1-click RCE via attacker-controlled content
- **Exposed gateways** bound to `0.0.0.0:18789` by default
- **Prompt injection** vulnerability ("lethal trifecta")
- **Bloated dependencies**: 385KB lockfile, 60+ npm packages

SafePincer fixes all of these while staying lightweight and fast.

## Features

| Feature | SafePincer | OpenClaw |
|---|---|---|
| Language | Rust | Node.js/TypeScript |
| Binary size | ~15MB | ~500MB+ (with node_modules) |
| RAM usage | <256MB | >1GB |
| Response latency | <1s | 2-5s |
| Default network exposure | **None** (localhost only) | `0.0.0.0:18789` |
| Prompt injection guard | ✅ Multi-layer | ❌ None |
| Workspace confinement | ✅ Symlink-safe | ❌ Partial |
| Sandbox support | ✅ Bubblewrap | ❌ None |
| LLM support | Ollama (local) + Cloud | Cloud only |
| Dependencies | ~25 crates | 60+ npm packages |

## Quick Start

### Prerequisites

- **Rust** 1.70+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **Ollama** (for local LLM): `curl -fsSL https://ollama.com/install.sh | sh`

### Install & Run

```bash
# Clone
git clone https://github.com/your-org/safepincer.git
cd safepincer

# Build
cargo build --release

# Pull a model (one-time)
ollama pull phi3:mini

# Run interactive REPL
./target/release/safepincer

# Or run a single task
./target/release/safepincer --task "What is sqrt(144) + 3^2?"
```

### Cloud LLM Mode

```bash
export SAFEPINCER_API_KEY="sk-your-key"
./target/release/safepincer --model-mode cloud --model-name gpt-4o
```

## Architecture

```
safepincer/
├── safepincer-core/       # Core agent runtime
│   ├── agent.rs           # Observe-Plan-Act-Reflect loop
│   ├── llm.rs             # OpenAI-compatible client (Ollama + Cloud)
│   ├── memory.rs          # SQLite session memory (4K token limit)
│   ├── sanitizer.rs       # Prompt injection guard
│   ├── confiner.rs        # Workspace path confinement
│   └── config.rs          # Env-var based configuration
├── safepincer-tools/      # Safe tool implementations
│   ├── math_tool.rs       # Pure Rust math evaluator
│   ├── file_tool.rs       # Workspace-confined file I/O
│   ├── browser_tool.rs    # Read-only HTTP browser
│   └── confirmation.rs    # Human-in-the-loop confirmation
├── safepincer-cli/        # CLI binary (REPL + single-task)
├── safepincer-tunnels/    # Secure communication
│   ├── outbound.rs        # HTTPS proxy (mTLS, rate limiting)
│   └── inbound.rs         # JSON-RPC 2.0 server
└── scripts/
    ├── sandbox.sh         # Bubblewrap sandbox runner
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
8. **Sandbox** — Optional bubblewrap isolation (read-only root FS, PID namespace, capability drop)
9. **Human Confirmation** — Required for sensitive tool calls
10. **Max Steps Guard** — Agent loop capped at 15 iterations

### SSRF Prevention

The browser tool blocks all private/local network addresses:
- `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`
- RFC 1918 ranges: `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`
- Link-local: `169.254.x.x`

## CLI Options

```
SafePincer 🦞 — Secure, lightweight AI agent

Usage: safepincer [OPTIONS]

Options:
  -w, --workspace <DIR>      Workspace directory [default: ./safepincer_workspace]
  -m, --model-mode <MODE>    LLM mode: "local" or "cloud" [default: local]
  -n, --model-name <NAME>    Model name [default: phi3:mini]
      --api-url <URL>        API base URL
      --api-key <KEY>        API key [env: SAFEPINCER_API_KEY]
      --max-steps <N>        Max agent steps per task [default: 15]
  -t, --task <TASK>          Run single task and exit
      --no-confirm           Disable confirmation prompts
  -h, --help                 Print help
  -V, --version              Print version
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `SAFEPINCER_WORKSPACE` | Workspace directory | `./safepincer_workspace` |
| `SAFEPINCER_LLM_MODE` | `local` or `cloud` | `local` |
| `SAFEPINCER_API_BASE_URL` | LLM API endpoint | `http://localhost:11434/v1` |
| `SAFEPINCER_API_KEY` | API key (cloud mode) | — |
| `SAFEPINCER_MODEL` | Model identifier | `phi3:mini` |
| `SAFEPINCER_MAX_STEPS` | Max loop iterations | `15` |
| `SAFEPINCER_TOOL_TIMEOUT` | Tool timeout (seconds) | `5` |

## Available Tools

| Tool | Description | Confirmation |
|---|---|---|
| `math_eval` | Evaluate math expressions (arithmetic, functions, constants) | No |
| `file_ops` | Read/write/append/list files in workspace | No |
| `browse_url` | Fetch and read web page content (read-only) | Yes |

## Sandboxed Execution

For maximum security, run SafePincer inside the bubblewrap sandbox:

```bash
# Install bubblewrap
sudo apt install bubblewrap

# Run in sandbox (no network)
./scripts/sandbox.sh --task "Calculate pi * e"

# Run in sandbox with network (for cloud LLM)
./scripts/sandbox.sh --enable-outbound --model-mode cloud
```

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
