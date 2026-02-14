# Phase 10: Exact OpenClaw Parity

## 10.1 Deep Analysis of OpenClaw Memory System
- [x] Audit all memory-related files in openclaw_reference/src/memory/
- [x] Audit memory tool implementation (memory-tool.ts)
- [x] Audit memory sync (sync-memory-files.ts, sync-session-files.ts)
- [x] Audit embeddings system (embeddings.ts, manager.ts)
- [x] Audit compaction system (compaction.ts, memory-flush.ts)
- [x] Document exact architecture: what uses MEMORY.md, what uses SQLite, what uses embeddings
- [x] Create implementation plan for exact parity

## 10.2 Implement Exact Memory System Parity
- [x] Match dual storage (MEMORY.md + SQLite-vec for embeddings)
- [x] Match vector/semantic search with embeddings
- [x] Match memory sync pipeline
- [x] Match compaction (LLM-based summarization)
- [x] Match memory citations

## 10.3 Streaming Responses (SSE)
- [ ] Audit OpenClaw streaming (pi-embedded-subscribe.ts)
- [x] Implement streaming in LlmClient
- [ ] Implement reasoning tag stripping in stream
- [ ] CLI real-time output

## 10.4 web_fetch Readability Extraction
- [ ] Audit OpenClaw web_fetch (web-fetch.ts)
- [ ] Add readability/content extraction to browse_url
