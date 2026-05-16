--- BEGIN REVIEW ---

Outside-lens review, fresh pass.

1. Production EVM prior art: no consensus for DTVM-style SPP.

- evmone has the closest shipped prior art: its advanced interpreter computes per-basic-block `gas_cost` in `BlockAnalysis`, emits `OPX_BEGINBLOCK`, and subtracts that block cost at block entry. That is block-entry precharge, not CFG-wide SPP gas shifting across predecessor/successor edges. Sources: ethereum/evmone `advanced_analysis.cpp`, `advanced_instructions.cpp`.
- revm charges `gas_table[opcode]` inside `Interpreter::step()` before executing the opcode. reth is built around the `reth_revm` crate, which is documented as glue integrating reth database/context with revm execution. Sources: bluealloy/revm `interpreter.rs`; reth.rs `reth_revm`.
- Erigon and Besu charge per operation in the interpreter loop. Erigon subtracts `operation.constantGas` / dynamic gas in `Run`; Besu runs an operation and then `frame.decrementRemainingGas(result.getGasCost())`. Sources: erigontech/erigon `interpreter.go`; hyperledger/besu `EVM.java`.
- Therefore the industry pattern is either per-op runtime metering or evmone-style block-entry precharge. I found no shipped evmone/revm/reth/Erigon/Besu implementation doing DTVM-style SPP path-cost shifting via dominator/natural-loop/SCC analysis. P2 is a DTVM-specific substrate cleanup, not an industry-aligned EVM direction.

Concrete alternative framing: "DTVM keeps SPP because its multipass JIT already consumes `GasChunkCostSPP`" is a defensible product-local argument; "production EVMs do this" is not.

2. P1 EVMAnalyzer wiring: likely layer inversion unless extracted.

- Local source says `src/evm` builds the `evm` object library from `evm_cache.cpp` and siblings (`src/evm/CMakeLists.txt:1-5`). The EVM frontend analyzer is in the compiler library, whose CMake appends `evm_frontend/evm_imported.cpp` and `evm_frontend/evm_mir_compiler.cpp` under `ZEN_ENABLE_EVM`, and links LLVM libs (`src/compiler/CMakeLists.txt:97-116`). `dtvmcore` only adds the compiler library under `ZEN_ENABLE_MULTIPASS_JIT` (`src/CMakeLists.txt:190-192`).
- Runtime currently invokes `COMPILER::EVMAnalyzer` only around JIT creation under `ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK`, then cache build only receives `Code`, `CodeSize`, `Revision`, and `CacheNeedsSPP` (`src/runtime/evm_module.cpp:103-137`). Cache-build consuming EVMAnalyzer directly would pull a downstream JIT/frontend analysis into the lower cache layer.
- The upside is real: `EVMAnalyzer` resolves constant jump targets through its abstract stack (`src/compiler/evm_frontend/evm_analyzer.h:666-710`), while SPP only accepts an immediately preceding `PUSH` (`src/evm/evm_cache.cpp:368-385`). The red-team report correctly names this precision gap (`redteam-precision-plus-omitted.md:10-23`).
- Known compiler pattern that works: stable, explicit feedback APIs such as LLVM `TargetTransformInfo` (target cost info exposed to IR-level passes) and PGO/FDO profiles. Known anti-pattern shape: LLVM middle-end depending on post-register-allocation spill decisions. LLVM documents register allocation inside codegen; MachineInstr remains SSA until register allocation, and after allocation there are no virtual registers. That is not a reusable upstream analysis contract.

Concrete alternative framing: do not include compiler headers from cache. Extract a small cache-safe jump-target summary/resolver library, or pass a versioned `pc -> target-or-dynamic` summary from module/JIT setup into cache build.

3. SCC condensation as primary CFG substrate: spot check supports "unusual".

- The red-team report says no production compiler it found uses SCC as the primary substrate for per-node intra-loop scheduling (`redteam-scc-dag.md:106-120`). My spot check supports that warning, not a stronger universal proof.
- V8 has `LoopTree` / `LoopFinder`; HotSpot C2 has `PhaseIdealLoop`; JikesRVM has `LSTGraph` / `LoopAnalysis`; Graal has `ControlFlowGraph`, `LoopsData`, and loop fragments; .NET RyuJIT uses `FlowGraphDfsTree` / flowgraph loop machinery. I did not find SCC-condensation DAG used as the main scheduling substrate in these implementations.
- This does not kill P2 because DTVM's current code already skips `InCycle` nodes before `lemma614Update` (`src/evm/evm_cache.cpp:1287-1364`), and the SCC red-team proof argues the loop fast-forward branch is metering-dead under current invariants (`redteam-scc-dag.md:17-44`). But it raises the proof burden: sell P2 as deletion of DTVM-specific dead loop machinery, not as a standard compiler loop-analysis replacement.

4. Real-contract benchmark methodology: roll your own corpus.

- evmone-bench is useful but not a real Solidity corpus. Locally it is a generated benchmark collection (`/home/abmcar/evmone/test/evm-benchmarks/README.md:1-8`) with 18 JSON files under `benchmarks/`, not a top-chain contract sample.
- I did not find a published revm/reth/evmone-trace/snarkVM cache-build corpus suitable for this question. Sourcify provides verified-contract datasets and BigQuery access; Solidity metadata exposes compiler version/settings/source hashes through CBOR metadata. Those are inputs for building a corpus, not a ready cache-build benchmark suite.
- Sampling should be codehash-deduped runtime bytecode, not address-deduped. Use strata by recent gas consumed, call count/deployment count, code size decile, JUMPDEST density, dynamic-jump ratio, proxy-vs-implementation label, and Solidity compiler version/metadata. Pin block range and chain. Report cache-build phase medians per stratum, not one average.
- "Top-by-gas >=10" is too narrow. A top-gas list can overrepresent a few protocols/proxies and miss code-shape diversity. Use top-by-gas as one stratum only.

5. The 21x N=100k framing is adversarial, not production.

- The problem statement uses N=100k JUMPDESTs and reports 44 ms vs 933 ms (`problem-statement.md:5-18`). EIP-170 caps mainnet deployed runtime code at `MAX_CODE_SIZE = 0x6000` bytes, i.e. 24,576 bytes. A deployed runtime contract cannot contain 100,000 JUMPDEST opcodes on mainnet; it cannot even contain more JUMPDESTs than bytes.
- So the 21x number is valid as algorithmic stress/DoS hygiene, but it is a bad production-performance headline. If real p99 runtime bytecode has far fewer JUMPDESTs, dom-CHK and especially P2 may be polishing a metric users do not hit.
- Required before P2: a real-corpus histogram of code size, JUMPDEST count, dynamic-jump count, SCC count/size, and per-phase cache-build time. Without that, the proposal is optimizing a synthetic fixture first and asking the real corpus to justify it later.

6. One big PR: possible historically, still the wrong default.

- DTVM has merged large performance/compiler PRs: #446 was 17 files / 1744 insertions / 78 deletions; #493 was 15 files / 2262 insertions / 30 deletions; #395 was 33 files / 4014 insertions / 226 deletions (`git show --stat --shortstat d44eb8e af60336 b1ab8d9`).
- But the current dom-CHK branch alone is already 12 files / 1511 insertions / 55 deletions and two unpushed commits (`git diff --shortstat upstream/main..HEAD`; `git log upstream/main..HEAD`). Adding P0/P1/P2 likely creates a PR larger than #446/#493, with more cross-layer risk than either.
- #446's own change doc shows the SPP surface is reviewer-heavy: mixed-precision CFG, over-approx safety, separate JIT/interpreter cost arrays, and SPP gating all had to be justified (`docs/changes/2026-04-05-gas-check-placement/README.md:16-73`). The new proposal stacks another dominator rewrite, P1 frontend/cache coupling, and P2 loop-substrate deletion.
- Also, the phase table includes wall-clock estimates (`problem-statement.md:14-18`), which violates this worktree's instruction that plans/specs must not contain macro duration estimates.

Concrete alternative framing: split by rollback boundary, not by narrative. PR A: dom-CHK plus P0 instrumentation/tests. PR B: P1 jump-target precision through an extracted cache-safe summary. PR C: P2 SCC DAG after real corpus proves loop/SCC phases matter, with shadow compare. If forced into one PR, keep commits/gates independently droppable and make P2 optional.

Sources:
- Local input: `/home/abmcar/changes/2026-05-16-evm-spp-overhaul/problem-statement.md:5-48`; `/home/abmcar/.claude/jobs/3d8995d3/redteam-scc-dag.md:17-44,106-120`; `/home/abmcar/.claude/jobs/3d8995d3/redteam-precision-plus-omitted.md:10-23,62-70,84-99`; `/home/abmcar/.claude/jobs/3d8995d3/redteam-cleanups.md:22-46,61-67`.
- Local code: `src/evm/evm_cache.cpp:368-425,1216-1379`; `src/compiler/evm_frontend/evm_analyzer.h:666-710`; `src/runtime/evm_module.cpp:103-137`; `src/evm/CMakeLists.txt:1-5`; `src/compiler/CMakeLists.txt:97-116`; `src/CMakeLists.txt:190-192`.
- Production EVMs: https://github.com/ethereum/evmone/blob/74614947a5798ee5465eed7f1e944fe1d4c0ea36/lib/evmone/advanced_analysis.cpp ; https://github.com/ethereum/evmone/blob/74614947a5798ee5465eed7f1e944fe1d4c0ea36/lib/evmone/advanced_instructions.cpp ; https://github.com/bluealloy/revm/blob/937e339e74be9abb29d1ce25869edee9ebbb42a5/crates/interpreter/src/interpreter.rs ; https://reth.rs/docs/reth_revm/index.html ; https://github.com/erigontech/erigon/blob/be461c2a54b5dccb181d8768c43f4686056155a0/execution/vm/interpreter.go ; https://github.com/hyperledger/besu/blob/61b98858ccb0a353a7267407a05f2cdbc46d114a/evm/src/main/java/org/hyperledger/besu/evm/EVM.java
- Compiler spot checks: https://github.com/v8/v8/blob/5cb092c41d9676c09bc9cae68e4973cfdcc43bb4/src/compiler/loop-analysis.h ; https://github.com/openjdk/jdk/blob/0e57fb963473f0589beaa84eb212423c2f059fd9/src/hotspot/share/opto/loopnode.hpp ; https://github.com/JikesRVM/JikesRVM/blob/5072f19761115d987b6ee162f49a03522d36c697/rvm/src/org/jikesrvm/compilers/opt/controlflow/LSTGraph.java ; https://github.com/oracle/graal/blob/edfd07f2958d750f5a71d4184bc97f633f6cc4dd/compiler/src/jdk.graal.compiler/src/jdk/graal/compiler/nodes/loop/LoopsData.java ; https://github.com/dotnet/runtime/blob/1acc89c305165239a5a824567a3176b6b3342790/src/coreclr/jit/flowgraph.cpp
- Methodology/protocol: https://eips.ethereum.org/EIPS/eip-170 ; https://docs.soliditylang.org/en/v0.8.35/metadata.html ; https://docs.sourcify.dev/docs/repository/index.html ; https://llvm.org/docs/CodeGenerator.html ; https://llvm.org/doxygen/TargetTransformInfo_8h.html

VERDICT: REFINE
--- END REVIEW ---
