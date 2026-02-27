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
| Sandbox | ✅ Platform-native (bwrap/sandbox-exec) | ❌ None |
| LLM support | Ollama (local) + Cloud | Cloud only |
| Dependencies | ~25 crates | 60+ npm packages |

## Quick Start

### Install

**🚀 Recommended: Bootstrap Installer (One Command)**

```bash
git clone https://github.com/your-org/zapclaw.git
cd zapclaw
./bootstrap.sh
```

The bootstrap script automatically installs:
- Rust toolchain (if needed)
- System dependencies (build-essential, pkg-config)
- **Sandbox tool** (Bubblewrap on Linux, built-in sandbox-exec on macOS)
- Ollama (for embeddings/indexing)
- Embedding model (`nomic-embed-text:v1.5`)
- ZapClaw binary

**📖 See [INSTALL.md](INSTALL.md) for detailed installation instructions.**

---

**🔧 Manual Installation**

```bash
# 1. Install Rust (one-time, skip if you already have it)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Install sandbox tool (platform-specific)
# Linux:
sudo apt install bubblewrap        # Debian/Ubuntu
# sudo dnf install bubblewrap      # Fedora
# sudo pacman -S bubblewrap        # Arch

# macOS: No installation needed! Uses built-in sandbox-exec
# If missing, run: xcode-select --install

# 3. Install Ollama (one-time, for memory embeddings)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull nomic-embed-text:v1.5   # Required for memory embeddings

# 4. Install ZapClaw
cargo install --path zapclaw-cli
```

That's it. Now `zapclaw` is available as a command from anywhere. It automatically runs inside a platform-native sandbox for security (bubblewrap on Linux, sandbox-exec on macOS).

### Run

**⚠️ IMPORTANT: Start Ollama first (for memory embeddings)**

ZapClaw requires Ollama to be running for memory search and embeddings. Start it before running ZapClaw:

```bash
# Start Ollama in background (runs on http://localhost:11434)
ollama serve &

# Verify Ollama is running
ollama ps
```

**Now run ZapClaw:**

```bash
# Interactive REPL (auto-creates home config on first run)
zapclaw

# Using project config (optional override)
zapclaw --init-config  # Creates ./zapclaw.json in current directory
# Edit ./zapclaw.json to override home config values
zapclaw

# Single task with CLI flags
zapclaw --api-url http://localhost:11434/v1 --model-name phi3:mini --task "What is sqrt(144) + 3^2?"

# Using environment variables (highest precedence)
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

1. **Platform-Native Sandbox** — Mandatory sandbox on all platforms:
   - **Linux**: Bubblewrap (read-only root FS, PID namespace, capability drop)
   - **macOS**: sandbox-exec (Seatbelt policy-based, default-deny)
   - **Android**: None (kernel limitations) - requires `--no-sandbox`
2. **Input Sanitization** — Multi-pattern regex guard against prompt injection
3. **Workspace Confinement** — All file I/O restricted to workspace (symlink-safe canonicalization)
4. **No Delete Operations** — File tool supports read/write/append only
5. **Network Isolation** — Zero default exposure; outbound/inbound tunnels disabled by default
6. **Rate Limiting** — Sliding-window limiter on outbound requests
7. **Domain Allowlisting** — Only approved domains reachable via outbound tunnel
8. **mTLS Authentication** — Mutual TLS for cloud API connections
9. **Human Confirmation** — Required for sensitive tool calls
10. **Max Steps Guard** — Agent loop capped at 15 iterations

### SSRF Prevention

The browser tool blocks all private/local network addresses:
- `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`
- RFC 1918 ranges: `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`
- Link-local: `169.254.x.x`

## Configuration

ZapClaw uses a layered configuration system with automatic home config creation:

### ⚡ Quick Setup (First Time)

**After running `./bootstrap.sh`, complete setup in 3 steps:**

#### Step 1: Edit Config File

```bash
# If config file doesn't exist, trigger auto-creation:
zapclaw --help

# Edit the global config file
nano ~/.zapclaw/zapclaw.json
```

**Set these required fields:**

```json
{
  "workspace_path": "./zapclaw_workspace",
  "api_base_url": "http://localhost:11434/v1",    // For Ollama
  "model_name": "phi3:mini",                       // For Ollama
  "max_steps": 15,
  "tool_timeout_secs": 30,
  "require_confirmation": true,
  "enable_egress_guard": true,
  "context_window_tokens": 128000,
  "memory_embedding_base_url": "http://localhost:11434/v1",
  "memory_embedding_model": "nomic-embed-text:v1.5",
  "memory_require_embeddings": true
}
```

**For different LLM providers:**

| Provider | `api_base_url` | `model_name` |
|----------|----------------|--------------|
| **Ollama (local)** | `http://localhost:11434/v1` | `phi3:mini`, `phi3:medium`, `llama3.2` |
| **OpenAI** | `https://api.openai.com/v1` | `gpt-4o`, `gpt-4o-mini` |
| **Anthropic** | `https://api.anthropic.com/v1` | `claude-sonnet-4-5-20250514` |
| **Groq** | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` |

#### Step 2: Create .env File (For API Keys)

**Desktop/Server:**
```bash
# Create .env in your project directory (or home directory)
cat > ~/.zapclaw/.env << 'EOF'
# ZapClaw Environment Variables
# API Keys and Secrets (NEVER commit this file)

# For cloud LLMs (OpenAI, Anthropic, etc.)
export ZAPCLAW_API_KEY=sk-your-key-here

# Optional: Web Search API (Brave Search)
export ZAPCLAW_SEARCH_API_KEY=your-brave-api-key

# Optional: Inbound tunnel for remote access
export ZAPCLAW_INBOUND_KEY=your-inbound-auth-key

# Optional: Telegram bot (requires BOTH token and allowed IDs)
export ZAPCLAW_TELEGRAM_TOKEN=your-telegram-bot-token
export ZAPCLAW_TELEGRAM_ALLOWED_IDS=123456789,987654321
EOF

# Secure the file
chmod 600 ~/.zapclaw/.env

# Add to shell profile to auto-load
echo 'source ~/.zapclaw/.env' >> ~/.bashrc  # or ~/.zshrc
source ~/.bashrc
```

**Mobile/Termux (Android):**
```bash
# Add directly to .bashrc (simpler for mobile)
cat >> ~/.bashrc << 'EOF'

# ZapClaw API Keys
export ZAPCLAW_API_KEY=sk-your-key-here
export ZAPCLAW_SEARCH_API_KEY=your-brave-api-key
export ZAPCLAW_TELEGRAM_TOKEN=your-telegram-bot-token
export ZAPCLAW_TELEGRAM_ALLOWED_IDS=123456789,987654321
EOF

source ~/.bashrc
```

#### Step 3: Run ZapClaw

**Desktop/Server:**
```bash
zapclaw
```

**Mobile/Termux (Android):**
```bash
zapclaw --no-sandbox
```

---

### Config File Locations

1. **Home config** (default, auto-created): `~/.zapclaw/zapclaw.json`
   - Automatically created on first run with safe defaults
   - Contains your personal preferences
   - Used everywhere unless explicitly overridden

2. **Project config** (optional override): `./zapclaw.json`
   - Created manually with `zapclaw --init-config`
   - Overrides home config values when present
   - Useful for project-specific settings

3. **Explicit path** (bypasses discovery): `--config <path>` or `ZAPCLAW_CONFIG_PATH`
   - Uses only the specified file
   - No home/project discovery

### Precedence Order

From lowest to highest priority:
1. **Built-in defaults**
2. **Home config** (~/.zapclaw/zapclaw.json)
3. **Project config** (./zapclaw.json, if exists)
4. **Environment variables**
5. **CLI flags** (highest priority)

### Config File Format

Home config is auto-created with this template:

```json
{
  "workspace_path": "./zapclaw_workspace",
  "api_base_url": "http://localhost:11434/v1",
  "model_name": "phi3:mini",
  "max_steps": 15,
  "tool_timeout_secs": 30,
  "require_confirmation": true,
  "enable_egress_guard": true,
  "context_window_tokens": 128000
}
```

**Important:** API keys are NEVER stored in config files. Set them via environment variables:
- `ZAPCLAW_API_KEY` - LLM API key (required for non-localhost endpoints)
- `ZAPCLAW_SEARCH_API_KEY` - Web search API key (optional, for Brave Search)
- `ZAPCLAW_INBOUND_KEY` - Inbound tunnel API key (for remote access)

### CLI Options

```
ZapClaw 🦞 — Secure, lightweight AI agent

Usage: zapclaw [OPTIONS]

Options:
  -c, --config <PATH>       Config file path (disables home+project discovery)
      --init-config         Create project config file template (./zapclaw.json) and exit
      --print-effective-config  Print merged configuration and exit
  -w, --workspace <DIR>     Workspace directory
  -n, --model-name <NAME>   Model name [env: ZAPCLAW_MODEL] (required)
      --api-url <URL>       API base URL [env: ZAPCLAW_API_BASE_URL] (required)
      --api-key <KEY>       API key [env: ZAPCLAW_API_KEY] (required for remote endpoints)
      --max-steps <N>       Max agent steps per task [default: 15]
  -t, --task <TASK>         Run single task and exit
      --no-confirm          Disable confirmation prompts
      --no-sandbox          Skip sandbox (dev only)
      --sandbox-no-network  Disable network inside sandbox
      --enable-inbound      Enable remote JSON-RPC server
      --enable-android       Enable Android device control via ADB
      --inbound-port <PORT> Inbound server port [default: 9876]
      --inbound-bind <ADDR> Bind address [default: 127.0.0.1]
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
| `android` | Control Android devices via ADB (tap, swipe, type, launch apps) | No* |

**Android Tool**: Requires `--enable-android` flag. Does not require confirmation by default (autonomous operation). See [ANDROID.md](ANDROID.md) for setup instructions.

## Sandbox

ZapClaw **always** runs inside a platform-native sandbox by default. The binary self-wraps: on startup, if not already sandboxed, it re-execs itself under the appropriate sandbox tool for the current OS.

**Linux — Bubblewrap (bwrap):**
- Read-only root filesystem
- Isolated PID, IPC, UTS namespaces
- All capabilities dropped
- Only the workspace directory is writable
- Isolated /tmp
- Process dies with parent

**macOS — sandbox-exec (Seatbelt):**
- Default-deny policy (only explicitly allowed operations permitted)
- Workspace read/write allowed; rest of filesystem read-only or denied
- Network controlled by policy (allow all by default; ZapClaw's egress guard handles allowlisting)
- Built into macOS — no installation required

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

**🤖 Android Device Control**: ZapClaw can also autonomously control Android devices via ADB. See [ANDROID.md](ANDROID.md) for complete setup guide.

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
- Agent still runs inside platform sandbox (bubblewrap on Linux, sandbox-exec on macOS)

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
