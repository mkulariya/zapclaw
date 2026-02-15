#!/usr/bin/env bash
#
# zapclaw-remote — Remote client for ZapClaw agent
#
# Sends tasks to a ZapClaw instance over SSH tunnel + JSON-RPC.
#
# Requirements: curl, jq, ssh, base64
#
# Environment variables:
#   ZAPCLAW_REMOTE_HOST   SSH host (user@server) — required for tunnel
#   ZAPCLAW_REMOTE_KEY    API key for authentication — required
#   ZAPCLAW_REMOTE_PORT   RPC port (default: 9876)
#
# Usage:
#   zapclaw-remote "What is 2+2?"                  # One-shot task
#   zapclaw-remote -i                               # Interactive mode
#   zapclaw-remote --health                         # Health check
#   zapclaw-remote --upload local.txt [remote.txt]  # Upload file
#   zapclaw-remote --download remote.txt [local.txt] # Download file
#   zapclaw-remote --list [pattern]                 # List workspace files

set -euo pipefail

PORT="${ZAPCLAW_REMOTE_PORT:-9876}"
HOST="${ZAPCLAW_REMOTE_HOST:-}"
KEY="${ZAPCLAW_REMOTE_KEY:-}"
BASE_URL="http://localhost:${PORT}/rpc"
SESSION_ID=""

# --- Helpers ---

die() { echo "Error: $1" >&2; exit 1; }

check_deps() {
    for cmd in curl jq; do
        command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' is required but not installed."
    done
}

check_key() {
    [ -n "$KEY" ] || die "ZAPCLAW_REMOTE_KEY not set. Set it to your ZapClaw inbound API key."
}

# Send a JSON-RPC request and return the result
rpc_call() {
    local body="$1"
    local timeout="${2:-120}"

    local response
    response=$(curl -s --max-time "$timeout" "$BASE_URL" \
        -H "Authorization: Bearer $KEY" \
        -H "Content-Type: application/json" \
        -d "$body" 2>&1) || die "Connection failed. Is ZapClaw running with --enable-inbound?"

    # Check for HTTP-level errors
    if echo "$response" | grep -q "Invalid or missing API key"; then
        die "Authentication failed. Check ZAPCLAW_REMOTE_KEY."
    fi

    # Check for JSON-RPC error
    local error
    error=$(echo "$response" | jq -r '.error.message // empty' 2>/dev/null)
    if [ -n "$error" ]; then
        echo "Error: $error" >&2
        return 1
    fi

    echo "$response"
}

# Check if tunnel/port is reachable
check_connection() {
    curl -s --max-time 2 "$BASE_URL" \
        -H "Authorization: Bearer $KEY" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"health","id":0}' >/dev/null 2>&1
}

# Open SSH tunnel if needed
ensure_tunnel() {
    # If we can already connect, tunnel exists or ZapClaw is local
    if check_connection; then
        return 0
    fi

    # Need SSH host to create tunnel
    [ -n "$HOST" ] || die "Cannot connect to localhost:${PORT} and ZAPCLAW_REMOTE_HOST not set.\nEither run ZapClaw locally or set ZAPCLAW_REMOTE_HOST for SSH tunnel."

    command -v ssh >/dev/null 2>&1 || die "'ssh' is required for remote tunneling."

    echo "Opening SSH tunnel to $HOST..." >&2
    ssh -f -N -L "${PORT}:localhost:${PORT}" "$HOST" 2>/dev/null \
        || die "Failed to open SSH tunnel to $HOST."

    # Wait for tunnel to be ready
    local attempts=0
    while ! check_connection; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 10 ]; then
            die "SSH tunnel opened but cannot reach ZapClaw on port $PORT."
        fi
        sleep 0.5
    done

    echo "Tunnel established." >&2
}

# --- Commands ---

cmd_health() {
    local resp
    resp=$(rpc_call '{"jsonrpc":"2.0","method":"health","id":1}' 5)
    echo "$resp" | jq -r '.result'
}

cmd_run_task() {
    local task="$1"

    # Escape the task for JSON
    local escaped
    escaped=$(printf '%s' "$task" | jq -Rs .)

    local body
    if [ -n "$SESSION_ID" ]; then
        local sid
        sid=$(printf '%s' "$SESSION_ID" | jq -Rs .)
        body="{\"jsonrpc\":\"2.0\",\"method\":\"run_task\",\"params\":{\"task\":${escaped},\"session_id\":${sid}},\"id\":1}"
    else
        body="{\"jsonrpc\":\"2.0\",\"method\":\"run_task\",\"params\":{\"task\":${escaped}},\"id\":1}"
    fi

    local resp
    resp=$(rpc_call "$body" 120) || return 1

    # Extract and display response
    local result
    result=$(echo "$resp" | jq -r '.result.response // empty')
    if [ -n "$result" ]; then
        echo "$result"
    else
        echo "$resp" | jq -r '.result'
    fi

    # Track session for multi-turn
    local new_sid
    new_sid=$(echo "$resp" | jq -r '.result.session_id // empty')
    if [ -n "$new_sid" ]; then
        SESSION_ID="$new_sid"
    fi
}

cmd_upload() {
    local local_path="$1"
    local remote_path="${2:-$(basename "$local_path")}"

    [ -f "$local_path" ] || die "File not found: $local_path"

    local encoded
    encoded=$(base64 < "$local_path")

    local escaped_path
    escaped_path=$(printf '%s' "$remote_path" | jq -Rs .)
    local escaped_content
    escaped_content=$(printf '%s' "$encoded" | jq -Rs .)

    local body="{\"jsonrpc\":\"2.0\",\"method\":\"upload_file\",\"params\":{\"path\":${escaped_path},\"content_base64\":${escaped_content}},\"id\":1}"

    local resp
    resp=$(rpc_call "$body" 30) || return 1

    local size
    size=$(echo "$resp" | jq -r '.result.size // "?"')
    echo "Uploaded: $local_path -> $remote_path ($size bytes)"
}

cmd_download() {
    local remote_path="$1"
    local local_path="${2:-$(basename "$remote_path")}"

    local escaped_path
    escaped_path=$(printf '%s' "$remote_path" | jq -Rs .)

    local body="{\"jsonrpc\":\"2.0\",\"method\":\"download_file\",\"params\":{\"path\":${escaped_path}},\"id\":1}"

    local resp
    resp=$(rpc_call "$body" 30) || return 1

    local content
    content=$(echo "$resp" | jq -r '.result.content_base64 // empty')
    if [ -z "$content" ]; then
        die "No content returned for: $remote_path"
    fi

    echo "$content" | base64 -d > "$local_path"

    local size
    size=$(echo "$resp" | jq -r '.result.size // "?"')
    echo "Downloaded: $remote_path -> $local_path ($size bytes)"
}

cmd_list() {
    local pattern="${1:-}"

    local body
    if [ -n "$pattern" ]; then
        local escaped
        escaped=$(printf '%s' "$pattern" | jq -Rs .)
        body="{\"jsonrpc\":\"2.0\",\"method\":\"list_files\",\"params\":{\"pattern\":${escaped}},\"id\":1}"
    else
        body='{"jsonrpc":"2.0","method":"list_files","params":{},"id":1}'
    fi

    local resp
    resp=$(rpc_call "$body" 10) || return 1

    echo "$resp" | jq -r '.result.files[] | "\(.path) (\(.size) bytes)"'
    local count
    count=$(echo "$resp" | jq -r '.result.count // 0')
    echo "---"
    echo "$count file(s)"
}

cmd_interactive() {
    echo "ZapClaw Remote (interactive mode)"
    echo "Type your tasks. Use 'exit' or Ctrl+C to quit."
    echo ""

    while true; do
        printf "zapclaw> "
        local input
        read -r input || break

        case "$input" in
            exit|quit|q)
                echo "Goodbye!"
                break
                ;;
            "")
                continue
                ;;
            /health)
                cmd_health
                ;;
            /list*)
                local pattern="${input#/list}"
                pattern="${pattern# }"
                cmd_list "$pattern"
                ;;
            /upload\ *)
                local args="${input#/upload }"
                # shellcheck disable=SC2086
                cmd_upload $args
                ;;
            /download\ *)
                local args="${input#/download }"
                # shellcheck disable=SC2086
                cmd_download $args
                ;;
            /session)
                if [ -n "$SESSION_ID" ]; then
                    echo "Session: $SESSION_ID"
                else
                    echo "No active session (will be created on first task)"
                fi
                ;;
            /help)
                echo "Commands:"
                echo "  /health            Health check"
                echo "  /list [pattern]    List workspace files"
                echo "  /upload f [name]   Upload file"
                echo "  /download f [name] Download file"
                echo "  /session           Show session ID"
                echo "  /help              Show this help"
                echo "  exit               Quit"
                echo ""
                echo "Anything else is sent as a task to the agent."
                ;;
            *)
                cmd_run_task "$input"
                ;;
        esac
        echo ""
    done
}

# --- Main ---

check_deps

case "${1:-}" in
    -h|--help)
        echo "Usage: zapclaw-remote [OPTIONS] [TASK]"
        echo ""
        echo "Options:"
        echo "  -i, --interactive    Interactive mode (multi-turn)"
        echo "  --health             Health check"
        echo "  --upload FILE [NAME] Upload file to workspace"
        echo "  --download FILE [NAME] Download file from workspace"
        echo "  --list [PATTERN]     List workspace files"
        echo "  -h, --help           Show this help"
        echo ""
        echo "Environment:"
        echo "  ZAPCLAW_REMOTE_HOST   SSH host (user@server)"
        echo "  ZAPCLAW_REMOTE_KEY    API key (required)"
        echo "  ZAPCLAW_REMOTE_PORT   Port (default: 9876)"
        ;;
    --health)
        check_key
        ensure_tunnel
        cmd_health
        ;;
    --upload)
        check_key
        ensure_tunnel
        shift
        cmd_upload "$@"
        ;;
    --download)
        check_key
        ensure_tunnel
        shift
        cmd_download "$@"
        ;;
    --list)
        check_key
        ensure_tunnel
        shift
        cmd_list "${1:-}"
        ;;
    -i|--interactive)
        check_key
        ensure_tunnel
        cmd_interactive
        ;;
    "")
        die "No task provided. Use -h for help, or -i for interactive mode."
        ;;
    *)
        check_key
        ensure_tunnel
        cmd_run_task "$*"
        ;;
esac
