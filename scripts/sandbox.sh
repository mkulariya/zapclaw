#!/usr/bin/env bash
# DEPRECATED: ZapClaw now auto-sandboxes itself.
#
# The zapclaw binary automatically re-execs inside bubblewrap on startup.
# You no longer need this script — just run: zapclaw [args]
#
# Use --no-sandbox to disable sandbox (development only).
# Use --sandbox-no-network to disable network inside sandbox.
#
# This script is kept for backwards compatibility and forwards to the binary.
#
# Original description:
# Runs ZapClaw inside a bubblewrap (bwrap) sandbox with restricted access.

set -euo pipefail

echo "NOTE: sandbox.sh is deprecated. ZapClaw now auto-sandboxes."
echo "  Just run: zapclaw [args]"
echo "  Use --no-sandbox to disable (dev only)."
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="${PROJECT_DIR}/target/release/zapclaw"
DEFAULT_WORKSPACE="${PROJECT_DIR}/zapclaw_workspace"

# --- Check prerequisites ---
if ! command -v bwrap &>/dev/null; then
    echo "❌ bubblewrap (bwrap) is not installed."
    echo "   Install it:"
    echo "     Debian/Ubuntu: sudo apt install bubblewrap"
    echo "     Fedora:        sudo dnf install bubblewrap"
    echo "     Arch:          sudo pacman -S bubblewrap"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "⚠️  Release binary not found at: $BINARY"
    echo "   Building release binary..."
    (cd "$PROJECT_DIR" && cargo build --release)
    if [ ! -f "$BINARY" ]; then
        echo "❌ Build failed. Cannot find: $BINARY"
        exit 1
    fi
fi

# --- Parse arguments for workspace path ---
WORKSPACE="$DEFAULT_WORKSPACE"
ENABLE_NETWORK=false

for arg in "$@"; do
    case "$arg" in
        --workspace=*) WORKSPACE="${arg#--workspace=}" ;;
        --enable-outbound) ENABLE_NETWORK=true ;;
        --enable-inbound) ENABLE_NETWORK=true ;;
    esac
done

# Create workspace if it doesn't exist
mkdir -p "$WORKSPACE"
WORKSPACE="$(cd "$WORKSPACE" && pwd)"

echo "🔒 ZapClaw Sandbox"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Binary:    $BINARY"
echo "  Workspace: $WORKSPACE"
echo "  Network:   $([ "$ENABLE_NETWORK" = true ] && echo "ENABLED" || echo "DISABLED")"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# --- Build bwrap arguments ---
BWRAP_ARGS=(
    # Read-only root filesystem
    --ro-bind / /

    # Writable workspace directory
    --bind "$WORKSPACE" "$WORKSPACE"

    # Writable /tmp (isolated)
    --tmpfs /tmp

    # Writable /dev (minimal)
    --dev /dev

    # New proc filesystem
    --proc /proc

    # Isolate PID namespace
    --unshare-pid

    # Isolate IPC namespace
    --unshare-ipc

    # Isolate UTS namespace (hostname)
    --unshare-uts
    --hostname "zapclaw-sandbox"

    # Don't inherit supplementary groups
    --new-session

    # Drop all capabilities
    --cap-drop ALL

    # Die when parent (this script) dies
    --die-with-parent

    # Set HOME to workspace
    --setenv HOME "$WORKSPACE"

    # Ensure our binary path is readable
    --ro-bind "$BINARY" "$BINARY"
)

# Network isolation (unless explicitly enabled)
if [ "$ENABLE_NETWORK" = false ]; then
    BWRAP_ARGS+=(--unshare-net)
else
    # Even with network, only allow loopback + existing interfaces
    echo "  ⚠️  Network access enabled — only allowlisted domains reachable via outbound tunnel"
fi

# --- Resource limits ---
# Set ulimits before exec
# Max 1GB virtual memory
ulimit -v 1048576 2>/dev/null || true
# Max 1024 open files
ulimit -n 1024 2>/dev/null || true
# Max 100 processes
ulimit -u 100 2>/dev/null || true
# No core dumps
ulimit -c 0 2>/dev/null || true

echo ""
echo "🦞 Launching ZapClaw in sandbox..."
echo ""

# --- Execute in sandbox ---
exec bwrap "${BWRAP_ARGS[@]}" "$BINARY" "$@"
