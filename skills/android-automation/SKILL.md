---
name: local-android-control-rust-termux-adb
version: 1.2.0
author: ZapClaw Project
description: Full local control of Android device via Rust binary + ADB (Termux, 127.0.0.1). Reads UI via uiautomator JSON. No root, no custom APK, 100% local. Security-first design.
tags: [android, adb, termux, uiautomator, rust-agent, local-only, zapclaw]
---

# Local Android Control (Rust + Termux + ADB)

You control the **Android device** that ZapClaw runs on (via Termux). Everything is 100% local. ADB connects via `127.0.0.1` (wireless debugging paired once).

**Tool name:** `android`

## Tool Schema (What the LLM Sees)

```json
{
  "type": "object",
  "properties": {
    "action": {
      "type": "string",
      "enum": ["get_screen", "screenshot", "tap", "long_press", "swipe", "type_text", "key", "open_app", "list_apps"]
    },
    "x": {"type": "integer", "minimum": 0, "maximum": 9999, "description": "X coordinate (0-9999)"},
    "y": {"type": "integer", "minimum": 0, "maximum": 9999, "description": "Y coordinate (0-9999)"},
    "x1": {"type": "integer", "minimum": 0, "maximum": 9999, "description": "Start X for swipe"},
    "y1": {"type": "integer", "minimum": 0, "maximum": 9999, "description": "Start Y for swipe"},
    "x2": {"type": "integer", "minimum": 0, "maximum": 9999, "description": "End X for swipe"},
    "y2": {"type": "integer", "minimum": 0, "maximum": 9999, "description": "End Y for swipe"},
    "duration_ms": {"type": "integer", "minimum": 100, "maximum": 10000, "default": 300, "description": "Swipe duration (ms)"},
    "text": {"type": "string", "description": "Text to type (ASCII characters only)"},
    "keycode": {"type": "string", "description": "Hardware key to press (e.g., KEYCODE_HOME)"},
    "package": {"type": "string", "description": "Android package name (e.g., com.whatsapp)"}
  },
  "required": ["action"]
}
```

## Core Perception-Action Loop (ALWAYS Follow)

1. **Plan** high-level steps in thinking trace
2. `open_app` (if needed)
3. `get_screen` → parse returned JSON tree
4. Decide action (tap center of best matching node)
5. Execute `tap`/`/`swipe`/`type_text`/`key`
6. `get_screen` again to verify
7. Repeat until goal met

**Never** guess coordinates. Always use JSON bounds from `get_screen`.

## Reading the UI Tree (get_screen Output)

`get_screen` returns clean JSON (parsed from `uiautomator dump`). Key fields per node:

```json
{
  "id": "e1",
  "text": "Login",
  "desc": "search button",
  "type": "ImageView",
  "cx": 958,
  "cy": 112,
  "bounds": "[892,56][1024,168]",
  "clickable": true
}
```

**Center coordinates are pre-calculated** - use `cx` and `cy` directly for tapping.

Prioritise nodes where:
- `clickable=true` OR `scrollable=true`
- `text` or `desc` matches intent
- Visible on current screen

## Safety & Security Rules (Critical — Never Violate)

- **Before ANY** money transfer, message send, delete, or install action → output exactly:  
  `CONFIRM: [exact action]` and wait for user reply.
- Never run commands outside the provided `android` tool
- All inputs validated: packages (regex), coordinates (0-9999), text (ASCII only), keycodes (allowlist)
- No arbitrary `adb shell` — hardcoded templates only
- Prefer `key: KEYCODE_BACK` to dismiss dialogs before dangerous actions

## Available Actions in Detail

- **`get_screen`** → Read UI hierarchy as compact JSON (200 actionable nodes max)
- **`screenshot`** → Save screenshot to workspace (returns file path)
- **`tap x y`** → Tap at coordinates (0-9999 range)
- **`long_press x y`** → Long press at coordinates (1000ms duration)
- **`swipe x1 y1 x2 y2 [duration_ms]`** → Swipe between points (default 300ms)
- **`type_text "text"`** → Type ASCII text only
- **`key keycode`** → Press hardware key (KEYCODE_HOME, KEYCODE_BACK, etc.)
- **`open_app package`** → Launch app by package name
- **`list_apps`** → List all third-party packages

## Supported Keycodes

Navigation: `KEYCODE_HOME`, `KEYCODE_BACK`, `KEYCODE_APP_SWITCH`  
Input: `KEYCODE_ENTER`, `KEYCODE_DEL`, `KEYCODE_TAB`, `KEYCODE_SPACE`  
Text Editing: `KEYCODE_COPY`, `KEYCODE_PASTE`, `KEYCODE_CUT`, `KEYCODE_SELECT_ALL`  
System: `KEYCODE_VOLUME_UP`, `KEYCODE_VOLUME_DOWN`, `KEYCODE_POWER`, `KEYCODE_CAMERA`, `KEYCODE_MENU`, `KEYCODE_SEARCH`, `KEYCODE_ESCAPE`

## Pro Tips for Rust Agent

- Center coordinates pre-calculated in JSON — use `cx`, `cy` directly
- `get_screen` is fast (~100ms) — always prefer over screenshot
- After `type_text`, often follow with `key: KEYCODE_ENTER`
- Common packages: `com.whatsapp`, `com.instagram.android`, `com.android.chrome`, `com.google.android.youtube`, `com.android.settings`
- For scrolling lists: `swipe` repeatedly + `get_screen` until target appears
- Multi-app tasks: `key: KEYCODE_HOME` to return to home screen between apps

## Common Mistakes to Avoid

- Using stale screen data after UI change → always `get_screen` after action
- Tapping wrong bounds → use pre-calculated `cx`, `cy` from JSON
- Forgetting device is asleep → wake device first
- Chaining actions without verification → one action per loop iteration
- No confirmation on sensitive actions
- Using screenshot when JSON works (slower)
- Typing non-ASCII text → will fail validation

## Example: "Open WhatsApp and send 'hello' to mom"

1. `open_app` package="com.whatsapp"
2. `get_screen` → find node with `text="Search"` or `desc="New chat"`
3. `tap` using node's `cx`, `cy` values
4. `type_text` "hello"
5. `get_screen` → verify text field has content
6. Tap the send button
7. `get_screen` → verify sent

**Confirmation required:** CONFIRM: Send message "hello" to mom?

This skill enables ZapClaw to autonomously control Android devices while staying tiny, private, and local-only.

Install once, use forever.
