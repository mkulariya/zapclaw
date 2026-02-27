# ZapClaw Quick Start Guide

**What to do AFTER running `./bootstrap.sh`**

This guide shows you exactly what to do after installation to get ZapClaw running.

---

## Desktop/Server Setup (Linux, macOS)

### Step 1: Start Ollama

ZapClaw requires Ollama to be running for memory embeddings. Start it first:

```bash
# Start Ollama in background
ollama serve &

# Verify Ollama is running
ollama ps
```

### Step 2: Edit Config File

The bootstrap script created a config file at `~/.zapclaw/zapclaw.json`, but `api_base_url` and `model_name` are **EMPTY by default**. You must set them.

```bash
nano ~/.zapclaw/zapclaw.json
```

**⚠️ IMPORTANT: You MUST change these two fields:**

```json
{
  "workspace_path": "./zapclaw_workspace",
  "api_base_url": "http://localhost:11434/v1",
  "model_name": "phi3:mini",
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

### Step 3: Set API Keys (for Cloud LLMs Only)

**Skip this step if using Ollama (local LLM).**

For cloud LLMs (OpenAI, Anthropic, etc.), create `~/.zapclaw/.env`. ZapClaw loads it automatically on startup — no shell sourcing needed:

```bash
cat > ~/.zapclaw/.env << 'EOF'
ZAPCLAW_API_KEY=sk-your-key-here
ZAPCLAW_SEARCH_API_KEY=your-brave-api-key
EOF

chmod 600 ~/.zapclaw/.env
```

You can also create a `.env` file in your project directory for project-specific settings. Local `.env` takes priority over `~/.zapclaw/.env`.

### Step 4: Run ZapClaw

```bash
zapclaw
```

That's it! ZapClaw is now running with:
- ✅ Ollama server for embeddings
- ✅ Configured LLM endpoint
- ✅ API keys loaded (if using cloud)
- ✅ Sandbox enabled (bubblewrap on Linux, sandbox-exec on macOS)

---

## Android/Termux Setup

### Step 1: Complete Bootstrap Installation

```bash
# In Termux
cd ~/zapclaw
./bootstrap.sh
```

### Step 2: Edit Config File

```bash
nano ~/.zapclaw/zapclaw.json
```

**For Android/Termux, use these settings:**

```json
{
  "workspace_path": "~/zapclaw_workspace",
  "api_base_url": "http://localhost:11434/v1",
  "model_name": "phi3:mini",
  "max_steps": 15,
  "tool_timeout_secs": 30,
  "require_confirmation": false,
  "enable_egress_guard": true,
  "memory_embedding_base_url": "http://localhost:11434/v1",
  "memory_embedding_model": "nomic-embed-text:v1.5",
  "memory_require_embeddings": true
}
```

### Step 3: Set API Keys (for Cloud LLMs Only)

**Skip if using local Ollama.**

Create `~/.zapclaw/.env` — ZapClaw loads it automatically:

```bash
cat > ~/.zapclaw/.env << 'EOF'
ZAPCLAW_API_KEY=sk-your-key-here
ZAPCLAW_SEARCH_API_KEY=your-brave-api-key
ZAPCLAW_TELEGRAM_TOKEN=your-telegram-bot-token
ZAPCLAW_TELEGRAM_ALLOWED_IDS=123456789,987654321
EOF

chmod 600 ~/.zapclaw/.env
```

### Step 4: Start Ollama

```bash
# Start Ollama in background
ollama serve &

# Verify it's running
ollama ps
```

### Step 5: Run ZapClaw

```bash
# Required flags for Android
zapclaw --no-sandbox
```

**For Android device control (requires ADB setup):**

```bash
# Install ADB
pkg install android-tools

# Enable USB debugging on your Android device:
# Settings → About Phone → Tap "Build Number" 7 times
# Settings → System → Developer Options → Enable "USB Debugging"

# Run with Android control enabled
zapclaw --enable-android --no-sandbox --no-confirm
```

---

## Troubleshooting

### Ollama Not Running

**Error message:**
```
⚠️  OLLAMA EMBEDDING SERVICE NOT RUNNING
```

**Solution:**
```bash
ollama serve &
```

### Model Not Pulled

**Error message:**
```
model 'phi3:mini' not found
```

**Solution:**
```bash
ollama pull phi3:mini
ollama pull nomic-embed-text:v1.5
```

### Config File Not Found

**Error message:**
``⛔ Config file not found
```

**Solution:**
```bash
# Trigger auto-creation
zapclaw --help

# Or create manually
mkdir -p ~/.zapclaw
nano ~/.zapclaw/zapclaw.json
```

### API Key Not Set (Cloud LLMs)

**Error message:**
```
⛔ API key is required for remote endpoints
```

**Solution:**
```bash
# Add to ~/.zapclaw/.env (loaded automatically by ZapClaw)
echo 'ZAPCLAW_API_KEY=sk-your-key-here' >> ~/.zapclaw/.env
chmod 600 ~/.zapclaw/.env
```

### Permission Denied (Sandbox Issues)

**Error message:**
```
⛔ Failed to initialize workspace confiner
```

**Solution (Linux/macOS):**
```bash
# Ensure bubblewrap is installed (Linux)
sudo apt install bubblewrap  # Debian/Ubuntu
sudo dnf install bubblewrap  # Fedora

# Or disable sandbox (not recommended)
zapclaw --no-sandbox
```

**Solution (Android/Termux):**
```bash
# Android doesn't support sandboxing - always use --no-sandbox
zapclaw --no-sandbox
```

---

## Quick Reference Commands

### Desktop/Server

```bash
# Start Ollama
ollama serve &

# Run ZapClaw
zapclaw

# Single task
zapclaw --task "Calculate sqrt(144)"

# With specific model
zapclaw --model-name phi3:mini --task "Explain Rust"
```

### Android/Termux

```bash
# Start Ollama
ollama serve &

# Run ZapClaw (required flags)
zapclaw --no-sandbox

# With Android control
zapclaw --enable-android --no-sandbox

# Keep device awake (prevents sleep)
termux-wake-lock

# Run in tmux session (prevents background termination)
tmux new -s zapclaw
zapclaw --no-sandbox
# Detach: Ctrl+B, then D
# Re-attach: tmux attach -t zapclaw
```

---

## Environment Variables Reference

| Variable | Purpose | Required For |
|----------|---------|--------------|
| `ZAPCLAW_API_BASE_URL` | LLM API endpoint | Always |
| `ZAPCLAW_MODEL` | Model name | Always |
| `ZAPCLAW_API_KEY` | LLM API key | Cloud LLMs only |
| `ZAPCLAW_SEARCH_API_KEY` | Web search API key | Optional (Brave Search) |
| `ZAPCLAW_TELEGRAM_TOKEN` | Telegram bot token | Optional (remote control) |
| `ZAPCLAW_TELEGRAM_ALLOWED_IDS` | Telegram user IDs | Optional (whitelist) |
| `ZAPCLAW_INBOUND_KEY` | Inbound tunnel API key | Optional (remote access) |

---

## Next Steps

Once ZapClaw is running:

1. **Try basic commands:**
   ```
   Calculate sqrt(144) + 3^2
   Create a file called notes.txt with today's meeting notes
   Read notes.txt
   ```

2. **Explore tools:**
   ```
   /tools
   /status
   /help
   ```

3. **Enable memory:**
   ```
   Remember that I prefer dark mode for code editors
   What are my preferences?
   ```

4. **Read full documentation:**
   - `README.md` - Complete feature overview
   - `INSTALL.md` - Detailed installation guide
   - `ANDROID.md` - Android device control guide
   - `TELEGRAM_INTEGRATION.md` - Remote control via Telegram

---

## Support

- **Issues**: https://github.com/mkulariya/zapclaw/issues
- **Documentation**: See `*.md` files in repository root
