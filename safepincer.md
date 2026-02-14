# SafePincer: Secure, Lightweight, and High-Performance Clone of OpenClaw

## Document Metadata
- **Document Title**: SafePincer Design and Development Requirements Document
- **Version**: 1.0
- **Date**: February 14, 2026
- **Author**: Grok AI (Synthesized from Conversation with User: Manish)
- **Purpose**: This document serves as a comprehensive staff engineer-level design specification, architecture blueprint, and end-to-end development flow for implementing SafePincer—a secure, faster, and lightweight replica of OpenClaw. It consolidates all details from the project discussions, providing clear requirements, procedures, and guidelines for a software engineer to implement the system from scratch.
- **Audience**: Software Engineers, Developers, and Reviewers.
- **Approval**: Pending review by lead engineer (e.g., Manish).
- **References**: Based on OpenClaw GitHub repo (github.com/openclaw/openclaw), security audits (e.g., BitSight, Astrix), and best practices from Rust/Python ecosystems, Tailscale/WireGuard, and agent frameworks like LangGraph.

## 1. Introduction and Project Overview
### 1.1 Project Background
OpenClaw is an open-source, autonomous AI agent and personal assistant that runs locally, performing tasks like managing files, browser automation, and integrations with messaging apps (e.g., WhatsApp, Telegram, Slack). It uses LLMs (e.g., from OpenAI/Anthropic) for decision-making, maintains long-term memory via local Markdown files, and supports extensible "skills" or plugins. Launched in late 2025, it gained rapid popularity (100K+ GitHub stars) due to its proactive, always-on design but faces significant security risks (e.g., prompt injections, exposed instances, malicious plugins) and performance issues (bloated dependencies, high RAM usage).

SafePincer is a redesigned clone addressing these flaws while retaining >95% of OpenClaw's utility. It applies the Pareto Principle (80/20 rule): Focus on 20% of features (core agent loop, safe tools, memory) delivering 80% value (autonomous task handling). Key differentiators:
- **Extreme Security**: Zero default exposures, confined to a single workspace folder, no risky integrations (e.g., no email/Slack), and optional secure tunnels for inbound/outbound comms.
- **Performance**: Faster (Rust core for concurrency/inference), lightweight (<500MB disk, <1GB RAM peak, <1s response latency).
- **Power**: Supports local/cloud LLMs, safe browser tasks via MCP (read-only), and a new secure communication system.
- **Name and Branding**: "SafePincer" evokes a secure "pinch" on tasks, maintaining the claw theme (optional lobster emoji 🦞).

### 1.2 Project Goals
- Create a fully local-first AI agent that's proactive and extensible without OpenClaw's risks.
- Ensure end-to-end security: No vulnerabilities to prompt injections, data leaks, or unauthorized access.
- Optimize for consumer hardware: Run efficiently on laptops/VMs without separate machines.
- Enable optional external interactions (e.g., cloud LLMs, remote commands) via super-secure tunnels.
- Provide a modular, hybrid language implementation for balance between speed (Rust) and ease (Python).

### 1.3 Scope
- **In Scope**: Core agent runtime, safe tools, memory system, local CLI, optional secure tunnels (inbound/outbound), lightweight containerization.
- **Out of Scope**: Community plugins, messaging integrations (e.g., WhatsApp/Telegram), full browser automation (limit to read-only), scheduling beyond on-demand, UI beyond CLI.
- **Assumptions**: Developer has access to Rust/Python toolchains, Git, and basic hardware (e.g., M1 Mac or equivalent). LLM models (e.g., Phi-3-mini) are downloadable.

## 2. Requirements
### 2.1 Functional Requirements
1. **Agent Runtime**:
   - Implement an observe-plan-act-reflect loop using LLMs for task processing.
   - Support local LLM inference (e.g., Phi-3-mini-Q4.gguf) and cloud LLMs (e.g., OpenAI/Anthropic) via secure outbound.
   - Handle tasks like math calculations, browser reading, and file ops within a confined workspace.
   - Require human confirmation for sensitive actions (e.g., outbound requests).

2. **Memory System**:
   - Store context in an encrypted local database (SQLite) within the workspace folder.
   - Limit memory to 4K tokens per session; append/retrieve efficiently.

3. **Safe Tools**:
   - **Math**: Secure evaluation (e.g., integrals, stats).
   - **Browser**: Read-only via Model Context Protocol (MCP) – inspect DOM/network, no executions/inputs.
   - **Files**: Read/write/append only in workspace; no deletes or external paths.
   - All tools must enforce path checks and timeouts (e.g., 5s).

4. **Communication Interfaces**:
   - **Primary**: Local CLI (REPL-like) over encrypted Unix socket.
   - **Outbound Tunnel**: Optional one-way HTTPS proxy for cloud LLMs/browser fetches (mTLS, ephemeral sessions, rate-limiting, user confirmation).
   - **Inbound Tunnel**: Optional secure remote command submission via Tailscale/WireGuard VPN mesh + JSON-RPC endpoint (mTLS auth, input filtering, sandboxed).

5. **Workspace Confinement**:
   - All operations (files, memory) restricted to `./safepincer_workspace` (0700 perms).
   - No system-wide access; override paths to prevent escapes.

6. **LLM Integration**:
   - Always available: Local fallback + cloud opt-in.
   - Secure key handling: Env vars or OS keychain; no plaintext storage.

### 2.2 Non-Functional Requirements
1. **Security**:
   - Zero inbound exposures by default; all optional features disabled initially.
   - Mitigate all OpenClaw risks: No prompt injections (filtering/guards), no malicious plugins, no exposed endpoints.
   - Use crypto best practices: AES-256 for encryption, mTLS for auth, integrity checks (hashes).
   - Audit logs for all actions; auto-shutdown on anomalies.

2. **Performance**:
   - RAM: <1GB peak.
   - Latency: <1s per response/inference.
   - Disk: <500MB install (including model).
   - Startup: <100ms for lightweight sandbox.

3. **Reliability**:
   - Graceful error handling (e.g., LLM failover).
   - Max steps per loop: 15 to prevent infinite runs.

4. **Usability**:
   - CLI flags for configs (e.g., --enable-inbound, --model cloud).
   - Documentation in README.md.

5. **Maintainability**:
   - Modular code: Separate crates/modules for core, tools, tunnels.
   - Test coverage: >80% unit/integration.

6. **Compatibility**:
   - OS: Linux/macOS (primary); Windows optional.
   - Hardware: CPU/GPU support for inference.

### 2.3 Constraints
- Languages: Rust (core/runtime/tunnels) + Python (tools via PyO3 interop).
- Deps: Minimal, audited (e.g., no vuln-prone like tar).
- No internet by default; optional tunnels only.
- Compliance: MIT license; no proprietary deps.

## 3. Architecture
### 3.1 High-Level Architecture
SafePincer follows a modular, layered design:
- **Presentation Layer**: Local CLI (Rust) + optional inbound tunnel (Tailscale + JSON-RPC).
- **Core Layer**: Agent runtime (Rust Tokio async loop) with LLM calls (local/cloud via outbound tunnel).
- **Tool Layer**: Hybrid tools (Rust wrappers calling Python where needed).
- **Data Layer**: Encrypted SQLite memory + workspace files.
- **Security Layer**: Cross-cutting: Sandboxing (bubblewrap), filtering, mTLS.
- **Deployment Layer**: Lightweight containerization for isolation.

Diagram (Text-based):
```
[User] --> [Local CLI / Inbound Tunnel (mTLS/VPN)] --> [Agent Runtime (Rust Loop)]
           |                                         |
           v                                         v
[Outbound Tunnel (HTTPS/mTLS)] <-- [LLM (Local/Cloud)]  [Safe Tools (Hybrid)]
                                                   |
                                                   v
[Workspace (Confined Folder)] <-- [Memory (Encrypted DB)]
```

### 3.2 Component Breakdown
1. **Agent Runtime**: Tokio-based event loop; nodes for observe/plan/act/reflect.
2. **Tunnels**:
   - Outbound: Reqwest proxy process; isolated.
   - Inbound: Tailscale daemon + RPC server; filtered proxy.
3. **Tools**: Pluggable traits in Rust; PyO3 for Python calls.
4. **Sandbox**: Bubblewrap wrapper around binary.

### 3.3 Data Flows
- Task Submission: CLI/socket --> Sanitize --> Agent Loop --> Tools/LLM --> Response.
- Secure Outbound: Agent --> Confirmation --> Proxy --> External (e.g., OpenAI) --> Response.
- Secure Inbound: Remote Client --> VPN --> RPC Endpoint --> Filter --> Agent.

### 3.4 Tech Stack
- Rust: Tokio, reqwest, llm, ring, rusqlite, pyo3, chrome-devtools, tailscale crate, jsonrpc.
- Python: sympy, requests (embedded via PyO3).
- Sandbox: Bubblewrap/Firejail.
- Build: Cargo + Pip (for Python parts).

## 4. Detailed Design
### 4.1 Module Designs
1. **Agent Module** (Rust Crate: safepincer-core):
   - Struct: Agent { llm: LlmClient, memory: MemoryDb, tools: ToolRegistry }.
   - Methods: run(task: String) -> String; with async loop.

2. **Tools Module** (Rust with PyO3):
   - Trait: Tool { fn execute(&self, input: String) -> Result<String>; }.
   - Impl: MathTool (calls Python sympy), BrowserTool (MCP via chrome-devtools), FileTool (std::fs with checks).

3. **Tunnels Module** (Rust Crate: safepincer-tunnels):
   - Outbound: struct OutboundProxy { client: ReqwestClient }; fn send_request(url: &str, body: Json) -> Response.
   - Inbound: struct InboundServer { tailscale: TailscaleClient, rpc: JsonRpcHandler }; fn start() -> ().

4. **CLI Module** (Rust Binary: safepincer-cli):
   - REPL loop: Read user input --> Socket send (mTLS) --> Receive response.

5. **Security Utilities** (Cross-cutting):
   - InputSanitizer: Regex/filter for injections.
   - Confiner: Path::starts_with(workspace).

### 4.2 Error Handling and Logging
- Use anyhow crate for errors.
- Log to workspace/log.txt (encrypted); levels: Info/Warn/Error.

## 5. Implementation Procedure and Flow
Follow Agile-like phases with Git branching (main, feat/*, fix/*). Total: 45-65 hours.

### 5.1 Phase 1: Setup (4-6h)
- Init Git repo; Cargo new safepincer.
- Add deps; setup PyO3.
- Generate mTLS certs script.
- Procedure: cargo build; test hybrid call (Rust -> Python func).

### 5.2 Phase 2: Core Runtime (6-8h)
- Implement agent loop/struct.
- Integrate local LLM (download model).
- Add memory DB.
- Procedure: Write unit tests; cargo test.

### 5.3 Phase 3: Tools (8-10h)
- Impl tools with wrappers.
- Add confirmation prompts.
- Procedure: Integration tests for each tool.

### 5.4 Phase 4: Communication/Tunnels (8-10h)
- Build local CLI/socket.
- Impl outbound proxy.
- Add inbound (Tailscale setup + RPC).
- Procedure: Test with mock remotes; enable/disable flags.

### 5.5 Phase 5: Sandboxing (4-6h)
- Write bubblewrap wrapper script.
- Integrate into build.
- Procedure: Verify isolation (e.g., strace).

### 5.6 Phase 6: Testing/Audit (8-10h)
- Unit/Integration: cargo test + pytest.
- Security: Fuzz (quickcheck), manual attacks.
- Perf: Benchmark (criterion crate).
- Procedure: Fix issues; achieve coverage.

### 5.7 Phase 7: Deployment/Docs (3-5h)
- Build release binary.
- Write README/usage.
- Procedure: Package (tar.gz); test on fresh env.

## 6. Testing Strategy
- **Unit**: Individual components (e.g., tool exec).
- **Integration**: End-to-end tasks.
- **Security**: Injection sims, tunnel breaches.
- **Perf**: Latency/RAM under load.
- Tools: Cargo test, Pytest, cargo-audit.

## 7. Deployment and Maintenance
- Run: `./safepincer --flags`.
- CI/CD: GitHub Actions for builds/tests.
- Updates: Cargo update; model pulls.
- Monitoring: Built-in logs.

## 8. Risks and Mitigations
- Risk: Hybrid Interop Issues – Mitigate: Fallback to pure Rust.
- Risk: Tunnel Setup Complexity – Mitigate: Detailed docs.
- Risk: LLM Costs – Mitigate: Local default.

## 9. Appendices
### 9.1 OpenClaw Key Learnings
- Avoid: Exposed gateways, permissive tools, vuln deps.
- Retain: Agentic design, local memory.

### 9.2 Timeline Estimate
- Week 1: Phases 1-3.
- Week 2: Phases 4-5.
- Week 3: Phases 6-7 + Review.

This document provides everything needed for implementation. For questions, refer to conversation history.
