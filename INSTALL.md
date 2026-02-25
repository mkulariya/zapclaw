# ZapClaw Installation Guide

## Quick Start (Bootstrap Installer)

The **recommended way** to install ZapClaw is using the bootstrap script, which automatically installs all dependencies:

```bash
# Clone the repository
git clone https://github.com/your-org/zapclaw.git
cd zapclaw

# Run the bootstrap installer
./bootstrap.sh
```

### What the Bootstrap Script Does

The bootstrap script (`bootstrap.sh`) automates the entire installation process:

1. **Installs Rust toolchain** (if not already installed)
2. **Installs system dependencies** (build-essential, pkg-config, curl)
3. **Installs sandbox tool** (Bubblewrap on Linux; built-in sandbox-exec on macOS — no install needed)
4. **Installs Ollama** (required for embeddings and indexing)
5. **Pulls Ollama embedding model**:
   - `nomic-embed-text:v1.5` - Embedding model for memory search
6. **Builds ZapClaw** from source
7. **Installs ZapClaw** to `~/.cargo/bin/zapclaw`

### Supported Platforms

- **OS**: Linux (Ubuntu, Debian, Fedora, Arch), macOS
- **Architecture**: x86_64, aarch64 (ARM64)
- **Requirements**:
  - 2GB RAM minimum (4GB recommended for building)
  - 6GB disk space (10GB recommended)

## Manual Installation

If you prefer to install components manually:

### 1. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### 2. Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config curl
```

**Fedora/RHEL:**
```bash
sudo dnf install -y gcc gcc-c++ make pkg-config curl
```

**macOS:**
```bash
xcode-select --install
```

### 3. Install Sandbox Tool

**Linux:**
```bash
# Ubuntu/Debian
sudo apt-get install -y bubblewrap

# Fedora
sudo dnf install -y bubblewrap

# Arch
sudo pacman -S bubblewrap
```

**macOS:**
No installation needed! ZapClaw uses macOS's built-in `sandbox-exec` for sandboxing (requires Xcode Command Line Tools).

If sandbox-exec is missing:
```bash
xcode-select --install
```

**Note:** 
- Linux uses Bubblewrap for namespace isolation
- macOS uses built-in sandbox-exec with Seatbelt policies
- Both provide equivalent security with platform-appropriate mechanisms

### 4. Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### 5. Pull Ollama Embedding Model

```bash
# Pull the embedding model (required for memory search)
ollama pull nomic-embed-text:v1.5
```

**Note:** You can use any LLM model (Ollama, OpenAI, Anthropic, etc.) for the agent. The embedding model is only used for memory indexing and search.

### 6. Build and Install ZapClaw

```bash
# Clone the repository
git clone https://github.com/your-org/zapclaw.git
cd zapclaw

# Build in release mode
cargo build --release

# Install to cargo bin
cargo install --path zapclaw-cli --force
```

## Verify Installation

```bash
# Check ZapClaw version
zapclaw --version

# Expected output: zapclaw 0.1.0
```

## Configuration

ZapClaw uses a layered configuration system. The first run will auto-create a config file at:

```
~/.zapclaw/zapclaw.json
```

### Default Configuration

```json
{
  "workspace_path": "./zapclaw_workspace",
  "api_base_url": "http://localhost:11434/v1",
  "model_name": "phi3:mini",
  "max_steps": 15,
  "tool_timeout_secs": 30,
  "require_confirmation": true,
  "memory_embedding_base_url": "http://localhost:11434/v1",
  "memory_embedding_model": "nomic-embed-text:v1.5",
  "memory_embedding_target_dims": 512,
  "memory_require_embeddings": true
}
```

## Running ZapClaw

### Interactive Mode (REPL)

```bash
# With local Ollama
ZAPCLAW_API_BASE_URL=http://localhost:11434/v1 \
ZAPCLAW_MODEL=phi3:mini \
zapclaw
```

### Single Task

```bash
# Local Ollama
ZAPCLAW_API_BASE_URL=http://localhost:11434/v1 \
ZAPCLAW_MODEL=phi3:mini \
zapclaw --task "What is sqrt(144) + 3^2?"
```

```bash
# Cloud LLM (OpenAI)
ZAPCLAW_API_BASE_URL=https://api.openai.com/v1 \
ZAPCLAW_API_KEY=sk-your-key \
ZAPCLAW_MODEL=gpt-4o \
zapclaw --task "Explain quantum computing"
```

## Memory & Embeddings

ZapClaw uses a hybrid search system combining:

- **BM25 keyword search** (FTS5 in SQLite)
- **Vector embeddings** (cosine similarity)

The embedding model `nomic-embed-text:v1.5` is used to generate embeddings for:
- File chunks (source code, documents)
- Session transcripts (conversation history)
- Search queries

### Memory Indexing

Memory indexing happens automatically in the background:
- Files in workspace are synced and chunked
- Sessions are indexed as they occur
- Embeddings are generated in batches (default: 32)

## Security

ZapClaw includes multiple security layers:

1. **Platform-Native Sandbox**:
   - **Linux**: Bubblewrap namespace isolation (PID, mount, network namespaces)
   - **macOS**: sandbox-exec with Seatbelt policies (default-deny, rule-based)
   - **Android/Termux**: No sandbox (kernel limitations) - use `--no-sandbox`
2. **Workspace Confinement**: File operations restricted to `./zapclaw_workspace`
3. **Input Sanitization**: Multi-layer prompt injection guards
4. **No Delete Operations**: File tool supports read/write/append only
5. **Human Confirmation**: Required for sensitive operations (network, execution)

## Troubleshooting

### Rust Installation Fails

If the Rust installation fails, try installing manually:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Sandbox Not Working (macOS)

macOS uses `sandbox-exec` (built-in Seatbelt), not Bubblewrap. It is located at `/usr/bin/sandbox-exec` and requires no installation. If it is missing, reinstall Xcode Command Line Tools:

```bash
xcode-select --install
```

If you still need to run without a sandbox (not recommended):

```bash
zapclaw --no-sandbox
```

### Ollama Connection Fails

Ensure Ollama is running:

```bash
# Check Ollama status
ollama ps

# Start Ollama service
ollama serve
```

### Models Not Pulled

Manually pull the required models:

```bash
ollama pull phi3:mini
ollama pull nomic-embed-text:v1.5
```

### Build Fails with OpenSSL Errors

On Linux, you may need to install OpenSSL development libraries:

```bash
# Ubuntu/Debian
sudo apt-get install -y libssl-dev pkg-config

# Fedora
sudo dnf install -y openssl-devel pkg-config
```

### zapclaw Command Not Found

Make sure `~/.cargo/bin` is in your PATH:

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$HOME/.cargo/bin:$PATH"

# Reload shell
source ~/.bashrc  # or source ~/.zshrc
```

## Advanced Installation

### Termux (Android)

Termux on Android is fully supported! The bootstrap script will automatically:

1. Detect Termux environment
2. Install dependencies (golang, cmake, git)
3. Build Ollama from source (takes 5-10 minutes)
4. Install embedding model
5. Build ZapClaw

**Manual Installation:**

```bash
# Install Termux from F-Droid or GitHub
# https://termux.dev/en/

# Update packages
pkg update && pkg upgrade

# Setup storage access
termux-setup-storage

# Run the bootstrap script
git clone https://github.com/your-org/zapclaw.git
cd zapclaw
./bootstrap.sh
```

**Important Notes for Termux:**
- ⚠️ **No sandbox**: Android kernel doesn't support namespace isolation. Always use `zapclaw --no-sandbox`
- ⏱️ **Build time**: Ollama compilation takes 5-10 minutes on ARM64 devices
- 🔋 **Battery**: Running LLMs drains battery quickly
- 💾 **Storage**: Ensure you have at least 4GB free space
- 📱 **Architecture**: Only ARM64 devices are supported
- 🔒 **Security**: Android's app sandbox provides isolation for Termux itself

### Custom Installation Directory

```bash
# Install to custom directory
cargo install --path zapclaw-cli --root /custom/path
export PATH="/custom/path/bin:$PATH"
```

## Updating ZapClaw

```bash
# Pull latest changes
cd /path/to/zapclaw
git pull

# Rebuild and reinstall
cargo install --path zapclaw-cli --force
```

## Uninstalling

```bash
# Remove the binary
rm ~/.cargo/bin/zapclaw

# Remove workspace (optional)
rm -rf ./zapclaw_workspace

# Remove config (optional)
rm -rf ~/.zapclaw
```

## Getting Help

- Run `zapclaw --help` for all options
- Check [README.md](README.md) for project overview
- See [CLAUDE.md](CLAUDE.md) for developer guide
- Report issues on GitHub

## Next Steps

After installation:

1. **Start the REPL**: `zapclaw`
2. **Run a single task**: `zapclaw --task "your task here"`
3. **Configure workspace**: Edit `~/.zapclaw/zapclaw.json`
4. **Check memory status**: Run `/status` in REPL
5. **Explore tools**: Run `tools` in REPL

Happy coding with ZapClaw! 🦞
