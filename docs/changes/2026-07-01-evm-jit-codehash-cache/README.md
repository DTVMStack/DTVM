# Change: EVM JIT codehash compiled-module cache

- **Status**: Implemented
- **Date**: 2026-07-01
- **Tier**: Full

## Overview

Add a Runtime-level EVM codehash cache so repeated executions of the same
runtime bytecode can reuse an already-created `EVMModule`, including analyzer
results, bytecode cache, fallback decision, and JIT code. Add an in-process
transaction replay harness to measure compile-once, execute-many behavior on
prepared EVM transaction corpora.

## Motivation

The 200-transaction replay corpus contains many repeated bytecode groups, but
the existing CLI replay path is mostly cold: each transaction loads and
compiles through its own module path, then unloads the module. This is useful
for cold-start attribution, but it does not measure the EVM JIT scenario where
a hot contract pays compilation once and then amortizes that cost across many
executions.

Recent EVM JIT work shows that compilation cost and IR scale are the main
long-tail bottlenecks. A codehash cache gives us a direct way to quantify when
JIT execution can repay compile cost, without claiming that cold one-shot
transactions are always faster than interpretation.

## Impact

### Affected Modules

- `runtime`: owns the new EVM codehash compiled-module cache and lookup API.
- `evm`: execution semantics are unchanged; cached modules still use existing
  interpreter/JIT paths.
- `cli` / tooling: ordinary `dtvm` behavior remains compatible; a new
  benchmark harness uses the cache API for in-process replay.
- `utils`: may be used for state loading, hex decoding, and address parsing.

### Affected Contracts

- Add a new `Runtime::getOrCompileCachedEVMModule(...)` API under
  `ZEN_ENABLE_EVM`.
- Existing `Runtime::loadEVMModule(...)` and `Runtime::unloadEVMModule(...)`
  remain compatible.
- Cached modules are owned by `Runtime` until `Runtime::cleanRuntime()`.

### Compatibility

No breaking CLI behavior is intended. The initial cache is in-process only:
cache entries disappear when the Runtime is destroyed. No persistent object
cache, eviction, or concurrent compile sharing is introduced in this change.

## Implementation Plan

### Phase 1: Runtime cache

- [x] Define an EVM code cache key based on bytecode Keccak-256, code size,
      revision, run mode, and JIT-relevant runtime config.
- [x] Add a Runtime-owned map from cache key to `EVMModuleUniquePtr`.
- [x] Add `getOrCompileCachedEVMModule(...)` that returns cache hit/miss
      metadata and compiles on miss.
- [x] Keep existing filename-based `loadEVMModule(...)` behavior unchanged.

### Phase 2: In-process replay harness

- [x] Add a tool that reads prepared transaction directories.
- [x] Group or process prepared transactions in one process while retrieving
      modules through the codehash cache.
- [x] Reset/load per-transaction state and create a fresh `EVMInstance` per
      execution.
- [x] Emit JSONL and summary JSON with cache hit/miss, compile timing,
      execution timing, return code, and per-codehash grouping.

### Phase 3: Documentation and verification

- [x] Update runtime and CLI module specs for the new experimental API/tool.
- [x] Add focused tests for cache key reuse and non-reuse across revision or
      config changes where practical.
- [x] Build `dtvm` and the new harness.
- [x] Run focused EVM tests and a small cached replay smoke test.

### Phase 4: A/B measurement and nested-call reuse

- [x] Extend lookup metadata with bytecode size, JIT-code presence, JIT-code
      size, fallback-to-interpreter state, and current cache entry count.
- [x] Add `--compare-jit-interpreter` so one harness invocation can run
      interpreter and multipass on the same prepared replay set.
- [x] Add per-codehash break-even estimates and fixed-N speedup projections to
      `summary.json`.
- [x] Route MockedHost internal CALL module loading through the Runtime
      codehash cache while preserving the existing per-transaction local module
      map.
- [x] Emit nested internal-call Runtime cache hit/miss counters in JSONL and
      summary output.

## Compatibility Notes

The first implementation intentionally avoids cross-process native-code
persistence. Persistent caches require CPU-feature validation, compiler-version
validation, relocation handling, executable memory mapping, and invalidation
logic; those are out of scope for this change.

The cached `EVMModule` still stores the Runtime's `evmc::Host *`. Therefore the
first implementation is scoped to a single Runtime and one Host object whose
state is reset between replayed transactions.

## Risks

- Cached module lifetime could outlive assumptions in existing unload paths.
  Mitigation: keep cached modules in a separate Runtime-owned pool and use the
  new API only from the new harness initially.
- Cache key omissions could incorrectly reuse JIT code across incompatible
  settings. Mitigation: include revision, run mode, gas-metering flag, greedy
  RA flag, and memory specialization profile in the key.
- State could accidentally be cached with code. Mitigation: cache only
  EVMModule; reload/reset MockedHost and create/reset EVMInstance for each
  transaction.
