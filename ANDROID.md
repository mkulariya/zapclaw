# Android Device Control with ZapClaw

> **⚠️ CRITICAL SECURITY WARNING**: Read the [Security Considerations](#security-considerations) section BEFORE using this feature. Android control gives ZapClaw extensive access to your device. NEVER use this on your primary phone or any device with sensitive data, banking apps, credentials, or personal accounts. Use a dedicated test device ONLY, factory reset before use, and keep it completely clean.

ZapClaw can autonomously control Android devices via ADB (Android Debug Bridge), enabling it to open apps, tap buttons, type text, swipe, read UI content, and more.

## What This Enables

With the `--enable-android` flag, ZapClaw gains these capabilities:

- **Read UI**: Get screen content as structured JSON (clickable elements, text, coordinates)
- **Tap**: Touch screen at specific coordinates
- **Swipe**: Perform swipe gestures
- **Type**: Input ASCII text
- **Press keys**: Simulate hardware key presses (Home, Back, Volume, Copy, Paste, etc.)
- **Launch apps**: Open apps by package name
- **List apps**: Enumerate installed third-party packages
- **Screenshots**: Capture screen to workspace

## Use Cases

- Automate repetitive mobile tasks
- Test mobile apps autonomously
- Interact with apps that lack APIs
- Control old Android phones as AI assistants
- Automate workflows across multiple apps

## Quick Setup (Termux on Android)

**ONE device. Everything runs on it.**

1. **Install Termux** from [F-Droid](https://f-droid.org/en/packages/com.termux/) or [GitHub Releases](https://github.com/termux/termux-app/releases)

2. **Open Termux** and run:
   ```bash
   # Update packages
   pkg update && pkg upgrade

   # Setup storage access
   termux-setup-storage

   # Clone ZapClaw
   cd ~
   git clone https://github.com/your-org/zapclaw.git
   cd zapclaw

   # Run bootstrap script (installs ZapClaw - takes 5-10 minutes)
   ./bootstrap.sh
   ```

3. **Complete ZapClaw Configuration**:

   **Step 3a: Trigger config creation (if needed)**
   ```bash
   # This auto-creates ~/.zapclaw/zapclaw.json
   zapclaw --help
   ```

   **Step 3b: Edit config file**
   ```bash
   nano ~/.zapclaw/zapclaw.json
   ```

   Set these fields:
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

   **Step 3c: Add API keys to .bashrc**
   ```bash
   cat >> ~/.bashrc << 'EOF'

   # ZapClaw Configuration
   export ZAPCLAW_API_KEY=sk-your-key-here
   export ZAPCLAW_SEARCH_API_KEY=your-brave-api-key
   export ZAPCLAW_TELEGRAM_TOKEN=your-telegram-bot-token
   export ZAPCLAW_TELEGRAM_ALLOWED_IDS=123456789,987654321
   export PATH="$PATH:$HOME/.cargo/bin"
   EOF

   source ~/.bashrc
   ```

   **Step 3d: Start Ollama (required for memory embeddings)**
   ```bash
   # Start Ollama in background
   ollama serve &

   # Verify Ollama is running
   ollama ps
   ```

4. **Install ADB (required for Android control)**:
   ```bash
   pkg install android-tools
   ```

5. **Enable USB Debugging** on your Android device:
   - Settings → About Phone → Tap "Build Number" 7 times
   - Settings → System → Developer Options → Enable "USB Debugging"

4. **Verify ADB** works:
   ```bash
   adb devices
   # Should show: XXXXXXXX  device
   ```

5. **Run ZapClaw**:
   ```bash
   # ⚠️ Make sure Ollama is running first!
   ollama serve &

   # Interactive REPL mode
   zapclaw --enable-android --no-sandbox --no-confirm

   # Single task mode
   zapclaw --enable-android --no-sandbox --task "Take a screenshot"
   ```

**Keep device awake (prevent sleep):**
```bash
# Install tmux and termux-api
pkg install tmux termux-api

# Acquire wakelock
termux-wake-lock

# Run ZapClaw in tmux session
tmux new -s zapclaw
zapclaw --enable-android --no-sandbox --no-confirm

# Detach: Ctrl+B, then D
# Re-attach: tmux attach -t zapclaw
```

That's it! ZapClaw is now running on your Android device and can control it autonomously.

## Available Android Actions

| Action | Description | Parameters |
|--------|-------------|------------|
| `get_screen` | Read UI hierarchy as JSON | None |
| `screenshot` | Capture screen to file | None |
| `tap` | Tap at coordinates | `x`, `y` (0-9999) |
| `long_press` | Long press at coordinates | `x`, `y` (0-9999) |
| `swipe` | Swipe between points | `x1`, `y1`, `x2`, `y2`, `duration_ms` (optional) |
| `type_text` | Type ASCII text | `text` (ASCII characters only) |
| `key` | Press hardware key | `keycode` (see list below) |
| `open_app` | Launch app by package name | `package` (e.g., com.whatsapp) |
| `list_apps` | List third-party packages | None |

### Supported Keycodes

Navigation: `KEYCODE_HOME`, `KEYCODE_BACK`, `KEYCODE_APP_SWITCH`  
Input: `KEYCODE_ENTER`, `KEYCODE_DEL`, `KEYCODE_TAB`, `KEYCODE_SPACE`  
Text Editing: `KEYCODE_COPY`, `KEYCODE_PASTE`, `KEYCODE_CUT`, `KEYCODE_SELECT_ALL`  
System: `KEYCODE_VOLUME_UP`, `KEYCODE_VOLUME_DOWN`, `KEYCODE_POWER`, `KEYCODE_CAMERA`, `KEYCODE_MENU`, `KEYCODE_SEARCH`, `KEYCODE_ESCAPE`

## Understanding `get_screen` Output

The `get_screen` action returns a compact JSON array of actionable UI elements:

```json
{
  "nodes": [
    {
      "id": "e1",
      "text": "Search",
      "desc": "",
      "type": "ImageView",
      "cx": 958,
      "cy": 112,
      "bounds": "[892,56][1024,168]",
      "clickable": true
    }
  ]
}
```

- `id`: Unique node identifier (e1, e2, ...)
- `text`: Visible text content
- `desc`: Content description
- `type`: UI element type
- `cx`, `cy`: Center coordinates for tapping
- `bounds`: Element bounds `[x1,y1][x2,y2]`
- `clickable`: Whether element is clickable

## Screenshots

Screenshots are saved to the workspace directory:

```
zapclaw_workspace/
└── .android_screenshots/
    ├── 2026-02-26_143022.png
    └── ...
```

The tool returns the file path:

```json
{
  "status": "success",
  "file": "workspace_path/.android_screenshots/2026-02-26_143022.png"
}
```

## Example Tasks

```bash
# Interactive REPL mode (chat with ZapClaw)
zapclaw --enable-android --no-sandbox --no-confirm

# Single task - list apps
zapclaw --enable-android --no-sandbox --task "What apps are installed?"

# Single task - open app
zapclaw --enable-android --no-sandbox --task "Open WhatsApp"

# Single task - screenshot
zapclaw --enable-android --no-sandbox --task "Take a screenshot"

# Multi-step automation
zapclaw --enable-android --no-sandbox --task "Open Instagram, search for 'cats', like the first 3 posts"
```

## Android Automation Skill

ZapClaw ships with a ready-made Android automation skill at `skills/android-automation/SKILL.md` in the repo. Copy it to your workspace to enable it:

```bash
cp -r skills/android-automation zapclaw_workspace/.skills/
```

ZapClaw picks it up automatically on the next run — no restart needed.

## Troubleshooting

### "adb: no permissions"

```bash
# Trigger authorization prompt
adb shell

# You'll see a popup on Android - tap "Allow"
# Then exit:
exit
```

### "Command not found: zapclaw"

```bash
# Make sure you ran bootstrap.sh
# ZapClaw is installed to your PATH
# Try with full path:
~/.local/bin/zapclaw --enable-android --no-sandbox
```

### "adb: no devices/emulators found"

```bash
# Make sure USB debugging is enabled
# Check Settings → System → Developer Options → USB Debugging
# Try restarting ADB:
adb kill-server && adb start-server
```

### Device goes to sleep during automation

```bash
# Keep screen awake while plugged in
adb shell settings put global stay_on_while_plugged_in 1

# Or disable screen timeout in Developer Options: "Stay Awake"
```

## Security Considerations

### ⚠️ Critical Security Warnings

**READ THIS CAREFULLY BEFORE USING ANDROID CONTROL**

With `--enable-android`, ZapClaw gains **extensive control** over your device:

- ✅ Can read all visible screen content (including passwords, messages, 2FA codes)
- ✅ Can tap any button on screen
- ✅ Can type into any text field
- ✅ Can launch any installed app
- ✅ Can press hardware keys (including power, volume, home)
- ✅ Can take screenshots of anything visible

**This means ZapClaw can potentially:**
- Read your passwords as you type them
- Read your 2FA codes from authenticator apps
- Send messages or emails on your behalf
- Make purchases through apps
- Transfer money through banking apps
- Access any data visible on screen

### 🚨 Absolute Requirements for Safe Usage

**To use Android control safely, you MUST:**

1. **Use a dedicated test device ONLY**
   - Never enable this on your primary phone
   - Never enable this on a device with sensitive data
   - Use an old/spare Android phone specifically for automation

2. **Keep the device CLEAN - BARE MINIMUM ONLY**
   - **NO banking apps** - Remove all banking, finance, payment, crypto apps
   - **NO credential storage** - No password managers, no authenticator apps (Google Authenticator, Authy, etc.)
   - **NO sensitive accounts** - No email with sensitive data, no corporate accounts, no cloud storage with personal files
   - **NO social media with personal info** - No logged-in Facebook, Instagram, Twitter with real identity
   - **NO payment methods** - No credit cards, no PayPal, no Venmo, no payment apps
   - **Factory reset the device before using ZapClaw** - Start from a clean slate

3. **Use throwaway/test accounts only**
   - Create dedicated test accounts for apps you automate
   - Never use your real Google/Apple ID on the device
   - Never use your real social media accounts
   - Never add real payment methods or cards
   - Use fake/test data wherever possible

4. **Keep USB debugging OFF when not automating**
   - Disable Developer Options when ZapClaw is not running
   - Revoke USB debugging authorization after each session
   - Physically disconnect the device when not in use

5. **Use a trusted network ONLY**
   - Never use public WiFi
   - Use your home network only
   - Consider using a separate VLAN or isolated network

### Input Validation

ZapClaw validates all inputs:

- **Package names**: Must match format `com.example.app` (regex validated)
- **Coordinates**: Bounded to 0-9999
- **Text**: ASCII only (Unicode requires clipboard workaround)
- **Keycodes**: Allowlist of 18 safe keys

No arbitrary `adb shell` commands are executed - all actions use hardcoded templates.

## Limitations

- **Unicode input**: Not supported (ASCII only via `input text` command)
- **WebView content**: May not be fully visible to UI dump (depends on app)
- **Background apps**: Can only interact with foreground app
- **System dialogs**: Some protected actions require additional permissions
- **Screen recording**: Not supported (only screenshots)

## Getting Help

If you encounter issues:

1. Check the [Troubleshooting](#troubleshooting) section
2. Verify ADB connection: `adb devices`
3. Test manually: `adb shell input tap 500 500`
4. Check ZapClaw logs: `RUST_LOG=debug zapclaw --enable-android`
5. Open an issue on GitHub with Android version, device model, and error message

## References

- [ADB Documentation](https://developer.android.com/studio/command-line/adb)
- [UI Automator](https://developer.android.com/training/testing/other-components/ui-automator)
- [Termux](https://termux.com/)
- [ZapClaw README](README.md)
