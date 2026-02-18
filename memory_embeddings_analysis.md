# Memory Embeddings Analysis (OpenClaw vs ZapClaw)

## 1) OpenClaw: current embeddings setup

OpenClaw memory search is embedding-driven and fully wired in runtime.

- Provider types: `openai`, `local`, `gemini`, `voyage` (`openclaw_reference/src/memory/embeddings.ts:32`).
- Local provider implementation:
  - Uses `node-llama-cpp` (in-process), not Ollama.
  - Loads GGUF embedding model via `modelPath`.
  - Default local model is `hf:ggml-org/embeddinggemma-300m-qat-q8_0-GGUF/embeddinggemma-300m-qat-Q8_0.gguf` (`openclaw_reference/src/memory/embeddings.ts:65`).
  - No remote API key needed for local.
- Auto provider selection:
  - If provider is `auto`, OpenClaw tries local first only when `local.modelPath` points to an existing local file (`openclaw_reference/src/memory/embeddings.ts:68`).
  - Then it tries remote providers in order (`openai`, `gemini`, `voyage`) (`openclaw_reference/src/memory/embeddings.ts:176`).
- Runtime wiring:
  - Provider is created during manager initialization (`openclaw_reference/src/memory/manager.ts:116`).
  - Search embeds query and runs vector/hybrid retrieval (`openclaw_reference/src/memory/manager.ts:228`).
  - Hybrid merge combines vector + BM25 (`openclaw_reference/src/memory/manager.ts:224`).

## 2) Are remote providers important for memory search?

Yes, for reliability and scale.

- Remote providers are the fallback/primary path when local is unavailable or not configured.
- Remote requires API keys (`openclaw_reference/docs/concepts/memory.md:99`).
- Remote batch indexing can speed up large backfills (`openclaw_reference/docs/concepts/memory.md:313`).

If local works reliably for your setup, remote is optional.
If you need portability, fast reindex at scale, or robust fallback, remote is useful.

## 3) What if we do not use embeddings provider at all?

In OpenClaw, no provider means memory search manager cannot initialize embeddings path, and memory tools effectively disable/return empty with error.

- `createEmbeddingProvider` can fail with "No embeddings provider available" (`openclaw_reference/src/memory/embeddings.ts:194`).
- Tool path returns disabled/error when manager is unavailable (`openclaw_reference/src/agents/tools/memory-tool.ts:54`).

Important nuance:
- If provider exists but query embedding is zero, BM25 keyword retrieval can still return results in hybrid flow (`openclaw_reference/src/memory/manager.ts:224`).

## 4) Can we do the same behavior in Rust using Ollama?

Yes.

You can achieve the same functional outcome (local embeddings + hybrid memory search) in Rust with Ollama's OpenAI-compatible embeddings endpoint (for example `http://localhost:11434/v1/embeddings`).
Architecture will differ from OpenClaw's `node-llama-cpp` in-process approach, but behavior can be equivalent for the product.

## 5) ZapClaw current state vs OpenClaw

ZapClaw already has major building blocks but not full runtime parity yet.

- Embedding provider exists and calls OpenAI-compatible `/embeddings` (`zapclaw-core/src/memory.rs:315`, `zapclaw-core/src/memory.rs:344`).
- `memory_search` currently uses `memory.search(...)` (`zapclaw-tools/src/memory_tool.rs:81`).
- In current path, vector stage is effectively inactive without query embedding wiring at search time (`zapclaw-core/src/memory.rs:999`).
- Chunks are inserted with empty embeddings by default (`zapclaw-core/src/memory.rs:615`).
- Advanced methods exist (`embed_all_chunks`, `search_hybrid`) but are not fully wired from runtime flow (`zapclaw-core/src/memory.rs:680`, `zapclaw-core/src/memory.rs:1068`).

Result: OpenClaw = full semantic/hybrid runtime. ZapClaw = partial scaffold, mostly keyword behavior today.

## 6) Effort estimate (Rust + Ollama parity)

- Basic usable path (embed chunks + embed query + hybrid merge): low/medium, about 1-3 days.
- Production parity (fallbacks, retries, timeouts, background sync/watch, status probes, robust tests): medium/high, about 1-2 weeks.

## 7) Memory and resource estimate

For OpenClaw's default local embedding model class (~300M):
- Model download size: ~0.6 GB (as documented).
- Typical runtime RAM for embeddings model process/context: ~1-2 GB.
- Additional memory/index overhead: ~200-800 MB depending corpus size/chunk count.
- Practical minimum machine target: ~4 GB RAM; smoother with 8 GB+.

## 8) Practical conclusion

- Yes, Rust + Ollama can deliver local embedding memory search without remote API keys.
- Remote providers are not mandatory for single-user local setups, but they are valuable as fallback and for large indexing jobs.
- If embeddings are removed entirely, semantic recall quality drops sharply (or memory search can become unavailable, depending wiring).
