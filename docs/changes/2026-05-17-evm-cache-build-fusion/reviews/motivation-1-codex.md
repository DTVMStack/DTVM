# Motivation red-team — outside-lens skeptic (Phase 0.5)

## Prior Art Collisions

### Bottom line

I did not find a direct public collision for DTVM's specific stack of "build an EVM cache with CFG edges, dominator/loop analysis, CSR adjacency, conditional SCC/Tarjan, and GasBlock layout compaction". What I did find is a strong pattern across production EVMs: they optimize the cheaper and externally familiar axis first, namely JUMPDEST validity analysis, jump tables/bitmaps, opcode caching, and interpreter dispatch. That makes DTVM's work technically plausible but externally under-framed: reviewers may ask why the claim is not presented as first-touch/JIT/cache warm-up latency or end-to-end execution impact.

### Implementation-by-implementation findings

| Implementation | Project URL | Concrete pointer | One-line summary |
|---|---|---|---|
| revm / revm-stage1 | https://github.com/bluealloy/revm | `crates/bytecode/src/legacy/analysis.rs` at commit `937e339e74be9abb29d1ce25869edee9ebbb42a5`: https://github.com/bluealloy/revm/blob/937e339e74be9abb29d1ce25869edee9ebbb42a5/crates/bytecode/src/legacy/analysis.rs; `crates/bytecode/src/legacy/jump_map.rs`: https://github.com/bluealloy/revm/blob/937e339e74be9abb29d1ce25869edee9ebbb42a5/crates/bytecode/src/legacy/jump_map.rs | revm analyzes legacy bytecode into a `JumpTable` bitvec and pads bytecode; this is jump-target validation, not DTVM-style CFG/dominator cache-build. I could not verify a distinct public project named `revm-stage1`; treat that name as UNVERIFIED unless the user supplies a repo/branch. |
| evmone advanced/baseline | https://github.com/ethereum/evmone | `lib/evmone/advanced_analysis.cpp` at commit `74614947a5798ee5465eed7f1e944fe1d4c0ea36`: https://github.com/ethereum/evmone/blob/74614947a5798ee5465eed7f1e944fe1d4c0ea36/lib/evmone/advanced_analysis.cpp; `lib/evmone/baseline_analysis.cpp`: https://github.com/ethereum/evmone/blob/74614947a5798ee5465eed7f1e944fe1d4c0ea36/lib/evmone/baseline_analysis.cpp | advanced analysis emits block metadata and jumpdest offset/target vectors while scanning bytecode; baseline builds a jumpdest bitset. I found no dominator/CFG pass analogous to DTVM's SPP cache-build. |
| py-evm | https://github.com/ethereum/py-evm | `eth/vm/code_stream.py` at commit `ffce74fa3c5d95682cdd5d84de82c80d60a56172`: https://github.com/ethereum/py-evm/blob/ffce74fa3c5d95682cdd5d84de82c80d60a56172/eth/vm/code_stream.py | py-evm lazily caches valid/invalid opcode positions and recursively checks PUSH-data disqualification; this is correctness/dispatch support, not CFG/dominator optimization. |
| geth/core/vm | https://github.com/ethereum/go-ethereum | `core/vm/contract.go` at commit `8a0223e8da596a409df02c11027320df97327e83`: https://github.com/ethereum/go-ethereum/blob/8a0223e8da596a409df02c11027320df97327e83/core/vm/contract.go | geth caches JUMPDEST analysis by code hash/local contract frame through `JumpDestCache`/`BitVec`; it validates `JUMPDEST` and code segment membership, not CFG/dominators. |
| Besu | https://github.com/besu-eth/besu | `evm/src/main/java/org/hyperledger/besu/evm/Code.java` at commit `6f232389501fe31bedcea3f25f2e4399c2d22196`: https://github.com/besu-eth/besu/blob/6f232389501fe31bedcea3f25f2e4399c2d22196/evm/src/main/java/org/hyperledger/besu/evm/Code.java | Besu lazily computes a 64-bit-chunk `jumpDestBitMask` for runtime dynamic jump validation; no CFG/dominator cache-build collision found. |
| reth | https://github.com/paradigmxyz/reth | `crates/evm/evm/Cargo.toml` at commit `49fe11041a9d8f58ebb4087dd9569a2cdbe4d027`: https://github.com/paradigmxyz/reth/blob/49fe11041a9d8f58ebb4087dd9569a2cdbe4d027/crates/evm/evm/Cargo.toml; root `Cargo.toml` workspace deps: https://github.com/paradigmxyz/reth/blob/49fe11041a9d8f58ebb4087dd9569a2cdbe4d027/Cargo.toml | reth's EVM crate depends on `revm`; for this question its bytecode-analysis prior art is revm's jump table, not a separate reth CFG/dominator implementation. |
| ethereumjs/vm | https://github.com/ethereumjs/ethereumjs-monorepo | `packages/evm/src/interpreter.ts` at commit `f7f2b2e6abaf09d57349aad9eddeeea6a5c73ba3`: https://github.com/ethereumjs/ethereumjs-monorepo/blob/f7f2b2e6abaf09d57349aad9eddeeea6a5c73ba3/packages/evm/src/interpreter.ts | ethereumjs runs jump analysis only once a JUMP/JUMPI/JUMPSUB is encountered, filling `validJumps`, `cachedPushes`, and cached opcode entries; this is lazy first-touch validation/caching, not full CFG/dominator construction. |

Opinion: the nearest prior-art collision is not "someone already did CSR dominator cache-build for EVM"; it is "production EVMs mostly avoid this whole axis and benchmark interpreter/runtime paths instead". That weakens the plan's motivational framing unless B explicitly proves that DTVM's heavier cache-build is visible in realistic workloads.

## Alternative Framings

The DTVM plan currently centers cache-build wall time. The implementation doc says the PR attacks `buildBytecodeCache` constant factors after PR A, including phase fusion, CSR adjacency, RPO sharing, and `GasBlock` compaction (`README.md:12-35`). It reports N=100k synthetic cache-build from 47.4 ms to 27.8 ms (`README.md:37-40`) and perf-summary reports pre-PR-A to this PR as 33.0x at N=100k (`perf-summary.md:11-17`, `perf-summary.md:28`). Round-2 Codex re-measured N=100k as 1.67x and -40.2% versus PR A (`round-2-codex.md:13-18`).

The outside-lens problem is scale validity. The same README says production EIP-170 caps code at 24,576 bytes, so the applicable region is at most N<=8000 and practically N=100-2000 (`README.md:331-335`). perf-summary states the same cap and says production mainly lands near the N=10k row, with this PR around +16% vs PR A in that region (`perf-summary.md:30-35`). README further labels the -41% number "algorithmic-DoS hygiene, not a production headline" (`README.md:331-335`) and says the N=100k ratio cannot be produced by deployed contract bytecode (`README.md:337-344`).

Opinion: cache-build wall time is a valid internal diagnostic, but it is not the strongest external axis. For reviewers, stronger axes are:

- first-touch warm-up latency: what a user or node pays the first time a contract is analyzed/executed;
- JIT compile/cache-build share of total transaction execution;
- end-to-end transaction execution time on real bytecode and calldata;
- tail latency under large initcode or algorithmic-DoS-shaped bytecode;
- runtime interpreter/JIT speed after the cache is built.

The 33x headline is misleading if used without the scale caveat. The doc is internally more honest than the plan summary: README already says N=100k is synthetic DoS scale (`README.md:337-344`), while the plan summary elevates 33x and 1.67x/40.2% without equally front-loading the N<=8000/real N=100-2000 constraint. I would not open a PR whose title/body leads with 33x unless the first paragraph says "synthetic cache-build DoS scale; production-scale follow-up pending".

## B's Methodology

Sourcify paired-ratio BCa cluster-bootstrap is a reasonable DTVM-specific validation framework if the goal is "does this cache-build work survive a real verified-contract corpus with paired HEAD vs upstream/main measurements?" README explicitly calls for re-running PR A's paired-ratio BCa harness as real-corpus follow-up (`README.md:479-483`), and perf-summary says all current PR numbers are synthetic while PR A's Sourcify paired harness could be rerun (`perf-summary.md:104-110`). That is a strong internal methodology because pairing controls per-contract variance and cluster bootstrap can keep repeated measurements from pretending to be independent contracts.

But as outside-lens evidence, Sourcify+BCa is not enough by itself. More recognizable external anchors are:

- ethereum/tests / GeneralStateTests: the Ethereum Tests docs describe GeneralStateTests as tests of state execution around a single transaction and mark the suite as actively supported: https://ethereum-tests.readthedocs.io/en/v6.0.0-beta.1/test_types/state_tests.html. DTVM already uses `evmone-statetest -k fork_Cancun` and reports 2723/2723 pass (`README.md:346-355`), so adding timing around this path is credible.
- evmone bench suite: evmone's public repo documents `evmone-bench` usage in its README/search result, and DTVM's README already uses an evmone-bench corpus for jump-resolution measurements (`README.md:121-131`). This is recognized by EVM implementers and directly comparable to another high-performance EVM.
- reth-bench: reth docs describe `reth benchmark` as feeding existing blocks into reth as execution payloads: https://reth.rs/docs/reth_bench/index.html. This is a better external story for end-to-end block/payload execution than contract-only synthetic N.
- geth/evm state runner and ethereum/tests JSON fixtures: these are less tailored to cache-build but more consensus-standard than a DTVM-only Sourcify harness.

Opinion: B should be reframed as a three-layer validation, not a single Sourcify statistic:

1. production corpus paired cache-build latency: Sourcify BCa, HEAD vs upstream/main;
2. recognized EVM micro/end-to-end suite: evmone-bench or ethereum/tests timing;
3. execution-level sanity: one block/payload or reth-bench-style end-to-end experiment if feasible.

The current plan says "Sourcify paired-ratio BCa cluster-bootstrap CI harness HEAD vs upstream/main; evmone-bench end-to-end supplemental." I would invert the rhetorical weight: Sourcify is the tailored internal harness; evmone-bench/ethereum-tests/reth-bench are the external credibility anchors.

## Premature Commitment Risk

A -> B -> C locks in shipping A before production-impact data lands. The plan's pro-ship facts are real: README marks the branch implemented on `perf/cache-build-fusion` (`README.md:3-8`), lists 11 implementation commits plus docs and review fixes (`README.md:210-258`; `git log` shows HEAD `de507df` over `592fd35`), and both R2 reviews passed according to the local review files (`round-2-codex.md:1-18`; `reviews/round-2-opus.md:1-45`). The plan also includes pre-push hardening items: add a `UseLinearSPP=false` GTest, update module docs for CSR/EdgeTables/32B layout, promote the change doc, run gate, push, open PR, watch CI.

The anti-ship facts are also real. Current perf evidence is synthetic-only (`README.md:479-483`; `perf-summary.md:110`), production-size relevance is explicitly smaller than N=100k (`README.md:331-344`), and the irreducible fallback branch lacks a dedicated unit test today (`README.md:169-172`, `README.md:420-428`). The plan says to fix that test before push, which is necessary but does not answer whether this optimization matters in production.

Opinion: do not fully run B before A if "B" means full CI-quality BCa harness plus evmone-bench integration; that could stale a branch that already has a coherent implementation and known safety gates. But do not open the PR before a B-lite smoke either. The minimum refinement is:

- before PR: run or produce one small real-corpus pilot table at production-scale N, even if not CI-grade, and use it only to decide PR framing;
- in PR title/body: lead with "cache-build synthetic stress + production-scale pilot", not "33x";
- after merge or during PR: make the full BCa harness the validation follow-up;
- before C: require full B data, because C's proposed wins are only ~0.5-1 ms each and the production cap makes them easy to overfit.

This is a REFINE, not KILL: A may still be worth shipping as algorithmic-DoS hygiene and code simplification if the PR is honest about production uncertainty.

## Kill Conditions

Concrete hypotheses that should abandon ABC for a different optimization axis:

1. Production-size speedup kill: if paired real-corpus contracts with CodeSize <= 24,576 B show median cache-build speedup vs PR A <5% and p95 absolute cache-build reduction <0.2 ms, stop C and shift to runtime/JIT execution hotspots. Rationale: README says production is practically N=100-2000 (`README.md:331-335`), so N=100k wins would not justify further cache-build micro-opts.

2. End-to-end invisibility kill: if end-to-end transaction execution on evmone-bench or ethereum/tests improves <1% median and <3% p95 after A, do not pursue C. Shift to interpreter/JIT runtime speed, host-call overhead, memory/storage gas paths, or U256 arithmetic, depending on measured hotspots.

3. First-touch latency kill: if first-touch warm-up latency on a Sourcify corpus is dominated by non-cache-build work and A reduces total first-touch latency by <5% at p95, abandon cache-build micro-opts and optimize the dominant warm-up component.

4. Scale-pathology kill: if speedup is concentrated only at synthetic N>=50k while N<=8000 is within noise (for example <5% with overlapping bootstrap confidence intervals), treat this branch as DoS hardening only and do not start C.

5. Correctness/maintenance kill: if adding the missing `UseLinearSPP=false` regression test exposes fallback misbehavior or if the CSR/EdgeTables/32B layout requires broad undocumented invariants beyond `src/evm/evm_cache.cpp`, stop A and reframe around correctness/testability before performance.

6. Prior-art/benchmark mismatch kill: if recognized external harnesses (`evmone-bench`, ethereum/tests timing, or reth-bench-style payload execution) show no visible benefit while only `evmCacheComplexityDemo` improves, abandon ABC's cache-build axis and use `ZEN_EVM_CACHE_PROFILE` only as an internal DoS regression guard.

## Verdict

REFINE.

Required refinements:

- Add the planned `UseLinearSPP=false` regression test before push; README already admits the dedicated fallback branch is untested (`README.md:420-428`).
- Update the module doc and PR body so CSR/EdgeTables/32B `GasBlock` are described as internal cache-build changes, not production throughput proof.
- Before opening PR, add a small real-corpus or production-scale pilot measurement sufficient to decide PR framing. Full BCa can remain post-merge/PR follow-up, but zero real-data PR framing is too inward-looking.
- Demote the 33x headline to algorithmic-DoS hygiene; front-load N<=8000 / practical N=100-2000 and the smaller production-scale expectation (`README.md:331-344`; `perf-summary.md:34`).
- Gate C on B with measurable thresholds. If production-size/end-to-end impact is invisible under the kill conditions above, switch to runtime/JIT execution or first-touch dominant-cost optimization instead of cache-build micro-opts.

VERDICT: REFINE
