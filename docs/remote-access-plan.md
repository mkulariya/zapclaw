# Secure Remote Access for ZapClaw — Design & Implementation Plan

## Context

ZapClaw is a secure, lightweight agent running on a local machine. The user wants to interact with it remotely — send tasks, receive responses, transfer files — from another machine, mobile device, etc. OpenClaw solves this with WhatsApp/Telegram/Slack integrations, but those are bloated and insecure. We need the **simplest, most secure** approach using existing tools.

---

## Analysis: What Options Exist?

### Option A: SSH Tunnel + JSON-RPC (Recommended)

```
[Mobile/Laptop] --SSH--> [Remote Machine] --localhost--> [ZapClaw Inbound:9876]
```

- **Security**: SSH is the gold standard — battle-tested encryption, public key auth, no passwords
- **Setup**: Zero new tools — SSH is preinstalled on every Linux/Mac
- **Mobile**: SSH apps exist for iOS (Blink, Termius) and Android (Termux, JuiceSSH)
- **File transfer**: `scp`/SFTP built into SSH — no extra protocol needed
- **How it works**:
  1. ZapClaw runs with `--enable-inbound` (binds JSON-RPC to `127.0.0.1:9876`)
  2. Remote user runs: `ssh -L 9876:localhost:9876 user@machine`
  3. Sends JSON-RPC requests to `localhost:9876` from their device
  4. Files via `scp user@machine:~/zapclaw_workspace/file.txt .`
- **Code needed**: Wire up existing inbound tunnel + add task processing + response mechanism
- **New dependencies**: Zero

### Option B: Tailscale Mesh + JSON-RPC

```
[Mobile] --Tailscale VPN--> [Remote Machine:9876]
```

- **Security**: WireGuard-based, zero-config VPN, very strong
- **Setup**: Install Tailscale on both devices, join network
- **Mobile**: Tailscale has iOS/Android apps with built-in file sharing
- **How it works**:
  1. Both devices join Tailscale network
  2. ZapClaw binds inbound tunnel to Tailscale interface IP
  3. Remote device connects directly to `machine.tailnet:9876`
- **Code needed**: Same as SSH + bind address config + optional Tailscale IP detection
- **New dependencies**: Tailscale (external)
- **Bonus**: Tailscale file sharing (`tailscale file send`) for ad-hoc transfers

### Option C: mTLS Direct Exposure

```
[Client with cert] --mTLS HTTPS--> [ZapClaw:9876]
```

- **Security**: Mutual TLS — both sides verify certificates
- **Setup**: Generate certs (gen_certs.sh exists), distribute client cert
- **Problem**: Cert distribution is painful, especially to mobile
- **Code needed**: Add TLS to inbound tunnel (currently plain HTTP)

### Option D: Bluetooth / Local Network

- **Bluetooth**: Too slow, range-limited, painful pairing, not practical
- **mDNS + Local WiFi**: Could work for same-network discovery, but no encryption without TLS
- **Verdict**: Not recommended for remote access

### Option E: Magic Wormhole / croc (File Transfer Only)

- **Good for**: One-off secure file transfers between machines
- **Not good for**: Ongoing task submission/response
- **Complements**: Could pair with SSH for tasks + wormhole for large files

---

## Recommendation: SSH Tunnel (primary) + Tailscale (optional)

**SSH is the answer.** Here's why:

1. **Already installed** — zero setup on server side
2. **Key-based auth** — no passwords, no tokens to manage
3. **Encrypted tunnel** — all traffic encrypted end-to-end
4. **Port forwarding** — ZapClaw stays on localhost, never exposed to network
5. **File transfer** — scp/SFTP built-in, no extra protocol
6. **Mobile** — SSH apps on every platform
7. **Auditing** — SSH logs all connections

Tailscale is the recommended **upgrade path** for users who want easier mobile access without manual port forwarding. It's additive — same JSON-RPC endpoint, different transport.

---

## What Already Exists in ZapClaw

| Component | Status | Location |
|-----------|--------|----------|
| Inbound JSON-RPC server | Implemented, not wired up | `zapclaw-tunnels/src/inbound.rs` |
| Outbound HTTPS proxy | Implemented, not wired up | `zapclaw-tunnels/src/outbound.rs` |
| Bearer token auth | Implemented | `inbound.rs` |
| Rate limiting | Implemented (outbound) | `outbound.rs` |
| mTLS cert generation | Complete | `scripts/gen_certs.sh` |
| Config flags | `enable_inbound`/`enable_outbound` exist | `config.rs` |
| CLI flags for tunnels | **Missing** | `main.rs` |
| Task processing loop | **Missing** | — |
| Response mechanism | **Missing** (returns "queued" only) | `inbound.rs` |
| File transfer RPC method | **Missing** | — |

---

## Implementation Plan

### Phase 1: Wire Up Inbound Tunnel (core remote access)

#### 1.1 Add CLI flags (`zapclaw-cli/src/main.rs`)

```
--enable-inbound          Enable remote JSON-RPC server
--inbound-port <PORT>     Inbound server port [default: 9876]
--inbound-bind <ADDR>     Bind address [default: 127.0.0.1]
--inbound-api-key <KEY>   API key for inbound auth [env: ZAPCLAW_INBOUND_KEY]
```

#### 1.2 Start inbound server in REPL mode (`main.rs`)

After agent creation, if `--enable-inbound`:
1. Create `InboundTunnel` with config
2. Call `tunnel.start()` to get `(JoinHandle, Receiver<InboundTask>)`
3. Spawn a background task that receives `InboundTask` from channel, runs through agent, and sends response back

#### 1.3 Add response mechanism (`inbound.rs`)

Current flow: client sends task → server returns `{ task_id, status: "queued" }` → task goes into channel → **nowhere**.

New flow:
- `submit_task` → returns `{ task_id }` immediately
- `get_result` → polls for result by task_id (or blocks with timeout)
- OR: `run_task` → synchronous: sends task, waits for agent response, returns result

Add `run_task` JSON-RPC method (simpler, better for SSH usage):
```json
// Request
{"jsonrpc": "2.0", "method": "run_task", "params": {"task": "What is 2+2?"}, "id": 1}

// Response (after agent completes)
{"jsonrpc": "2.0", "result": {"response": "The answer is 4.", "session_id": "..."}, "id": 1}
```

#### 1.4 Add file transfer RPC methods (`inbound.rs`)

```json
// Upload file to workspace
{"method": "upload_file", "params": {"path": "data.csv", "content_base64": "..."}}

// Download file from workspace
{"method": "download_file", "params": {"path": "results.txt"}}
// Returns: {"content_base64": "...", "size": 1234}

// List workspace files
{"method": "list_files", "params": {"pattern": "*.csv"}}
```

All file paths validated through Confiner (workspace-confined).

#### 1.5 Input sanitization on inbound tasks

Before passing to agent, all inbound tasks go through `InputSanitizer::sanitize()`.

### Phase 2: Wire Up Outbound Tunnel (optional, for browser/LLM)

#### 2.1 Add CLI flags

```
--enable-outbound         Enable outbound HTTPS proxy
--allowed-domains <LIST>  Comma-separated allowed domains
--client-cert <PATH>      mTLS client certificate
--client-key <PATH>       mTLS client key
--ca-cert <PATH>          CA certificate for server verification
```

#### 2.2 Route browser_tool and LLM through outbound tunnel when enabled

### Phase 3: Tailscale Integration (optional upgrade)

#### 3.1 Auto-detect Tailscale IP

```rust
fn detect_tailscale_ip() -> Option<String> {
    // Run: tailscale ip -4
    // Returns Tailscale IPv4 address if available
}
```

#### 3.2 Add `--inbound-bind tailscale` shortcut

Auto-detects and binds to Tailscale IP instead of localhost.

---

## User Experience

### SSH (Primary — Zero Setup)

**Server side:**
```bash
# Start ZapClaw with remote access
zapclaw --enable-inbound --inbound-api-key "my-secret-key"
```

**Client side (laptop/mobile):**
```bash
# Open SSH tunnel
ssh -L 9876:localhost:9876 user@my-server

# Send a task
curl -X POST http://localhost:9876/rpc \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"run_task","params":{"task":"List all .rs files"},"id":1}'

# Upload a file
curl -X POST http://localhost:9876/rpc \
  -H "Authorization: Bearer my-secret-key" \
  -d '{"jsonrpc":"2.0","method":"upload_file","params":{"path":"data.csv","content_base64":"..."},"id":2}'

# Transfer files directly
scp user@my-server:~/zapclaw_workspace/output.txt .
```

### Tailscale (Upgrade — Easier Mobile)

```bash
# Server: bind to Tailscale interface
zapclaw --enable-inbound --inbound-bind tailscale --inbound-api-key "my-key"

# Client: connect directly via Tailscale network
curl http://my-server.tailnet:9876/rpc ...
```

---

## Security Layers (Defense in Depth)

1. **Transport encryption**: SSH tunnel (or Tailscale WireGuard)
2. **API key auth**: Bearer token on every request (even over SSH — defense in depth)
3. **Localhost binding**: Server never exposed to public network by default
4. **Input sanitization**: All inbound tasks go through `InputSanitizer`
5. **Workspace confinement**: File uploads/downloads confined to workspace
6. **Sandbox**: Agent still runs inside bubblewrap sandbox
7. **Rate limiting**: Can add to inbound tunnel
8. **Max concurrent**: Inbound queue limited to 5 concurrent tasks

---

## Files to Modify/Create

| File | Changes |
|------|---------|
| `zapclaw-cli/src/main.rs` | Add CLI flags, start inbound server, task processing loop |
| `zapclaw-tunnels/src/inbound.rs` | Add `run_task`, `upload_file`, `download_file`, `list_files` methods |
| `zapclaw-core/src/config.rs` | Add env vars for inbound config |
| `README.md` | Add remote access documentation |

---

## Verification

```bash
# Build
cargo build

# Test 1: Start with inbound enabled
zapclaw --enable-inbound --inbound-api-key test123 &

# Test 2: Health check
curl -s http://localhost:9876/rpc \
  -H "Authorization: Bearer test123" \
  -d '{"jsonrpc":"2.0","method":"health","id":1}'

# Test 3: Submit task
curl -s http://localhost:9876/rpc \
  -H "Authorization: Bearer test123" \
  -d '{"jsonrpc":"2.0","method":"run_task","params":{"task":"What is 2+2?"},"id":2}'

# Test 4: File upload
echo "test data" | base64 | xargs -I{} curl -s http://localhost:9876/rpc \
  -H "Authorization: Bearer test123" \
  -d '{"jsonrpc":"2.0","method":"upload_file","params":{"path":"test.txt","content_base64":"{}"},"id":3}'

# Test 5: Auth rejection (no key)
curl -s http://localhost:9876/rpc \
  -d '{"jsonrpc":"2.0","method":"health","id":1}'
# Should return 401

# Test 6: SSH tunnel test
ssh -L 9876:localhost:9876 user@localhost &
curl -s http://localhost:9876/rpc ...

# All existing tests still pass
cargo test
```
