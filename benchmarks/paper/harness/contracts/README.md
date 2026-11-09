# Contract Wasm smoke runner

This is a standalone correctness and setup harness for a small, stateless
subset of the archived contracts. It runs the **same Wasm bytes and native host
implementation** on DTVM interpreter, singlepass, eager multipass and lazy
multipass, and Wasmtime 45. It is not the original paper's `test_vmbench`.
Each runner invocation creates a fresh module instance and performs one call.

## Cases and semantic findings

| Case | Input | Expected result |
|---|---|---|
| Archived `merkle_proof.wat` | `benchmark()`, selector `8903c5a2` | ABI bool true; eight proof levels, 91 MiMC rounds per hash |
| New `bench_c/merkle_valid.c` | same selector | true for a valid proof; append byte `01` to corrupt one sibling and expect false |
| Archived `generative_nft.wat` | `generate(uint256)`, selector `4a7dd523` | independent 256-bit reference; test token IDs 0, 1, 2 |
| Archived `fibonacci_30.wat` | `fibonacci(20)`, selector `61047ff4` | 6765, matching the paper call parameters |

The archived Merkle WAT is **not semantically equivalent to the adjacent
`MerkleProof.sol` as currently checked in**. The Solidity `benchmark()` builds
its root with `mimcHash(hash, proof[i])` at every level, but verifies odd levels
with reversed operands; the independent Python reference returns false. The WAT
has an odd/even branch during root construction and returns true. It and the
new C valid-proof case produce the same diagnostic sequence of crypto host
operations for the fixed input. This observation does not establish the WAT's
full source provenance or that other artifacts share these semantics. Further,
`CALLS.md` says ten levels while this WAT and the adjacent Solidity case use
eight. The WAT differs byte-for-byte from the archived paper-time hex artifact;
do not label this result a reproduction of the paper-time binary.

The new C case deliberately implements a consistent eight-level proof with
matching left/right positions. It is a new workload, not a rewrite proven
identical for arbitrary inputs to the archived contract or paper-time source.
Its optional fifth calldata byte only selects a corrupted-proof test vector.
`merkle_valid.wat` and all `.wasm` files are generated into the build output.

## Host contract

The shared C++ host supports only the imports needed by these cases:
`getCallDataSize`, `callDataCopy`, `getCallValue`, `finish`, `revert`,
`getCodeSize`, `codeCopy`, `keccak256`, `addmod`, and `mulmod`. Calldata is
explicit, call value is zero, and code bytes are represented with the DTVM
SolSDK mock's four-byte big-endian length prefix. Copy operations zero-pad
past the source and validate all guest memory spans. `addmod`/`mulmod` take
and produce **big-endian** 32-byte integers; intermediate arithmetic is wide
enough for the full 256-bit operand range, and zero modulus yields zero.
Keccak uses the repository's Ethereum Keccak implementation, not SHA3-256.
`finish` and `revert` terminate execution and capture output; unhandled imports
fail module instantiation. No state, storage, gas accounting, deployment,
external calls, event logs, or re-entrancy are implemented.

The Wasmtime and DTVM adapters share the computation, but use different
runtime callback and memory-validation APIs. Trace hashing is disabled by
default; `--trace` enables a non-cryptographic FNV diagnostic of crypto calls.
Counts are always enabled. Neither count nor trace should be assumed free in
future measurements. Host operations and engine/host boundary costs must be
measured separately when evaluating compiler performance. The lazy adapter
uses DTVM's internal `RuntimeConfig` because its public C API does not expose
lazy mode; the build script enforces the same DTVM checkout and derives its
feature defines from the configured CLI build. This is an internal test harness,
not a stable embedding API.

A normal `finish` traps out of Wasm before ordinary stack cleanup. The runner
therefore uses a fresh instance per invocation. Repeated calls on an existing
instance require a separately designed reset/state-lifecycle protocol; do not
interpret a shell loop around this runner as steady-state execution.

## Build and verify

Prerequisites: a configured **Ninja** DTVM Release build from this same checkout
with `dtvm`, singlepass and multipass enabled; LLVM 15, Boost headers; Clang
with wasm32/wasm-ld, WABT (`wat2wasm`, `wasm2wat`), Python 3 and PyCryptodome;
Wasmtime **45.0.0 C API**, not merely its CLI. No network access is needed by
the runner. For example, from the repository root:

```bash
# Configure DTVM according to the repository build docs, then:
cmake --build "$DTVM_BUILD" --target dtvm -j 4

# Linux x86-64 official C API release; unpack outside the source tree.
curl -L --fail https://github.com/bytecodealliance/wasmtime/releases/download/v45.0.0/wasmtime-v45.0.0-x86_64-linux-c-api.tar.xz -o /tmp/wasmtime45-capi.tar.xz
tar -xf /tmp/wasmtime45-capi.tar.xz -C /tmp
export WASMTIME_CAPI=/tmp/wasmtime-v45.0.0-x86_64-linux-c-api
# SHA256 of the archive used in the validation below:
# 95959e7a4cc4bfc12bbe45c9dea82cf45dd5b4321d9163e66343c50728429129

python3 -m pip install -r benchmarks/paper/harness/contracts/requirements.txt
benchmarks/paper/harness/contracts/build_inputs.sh benchmarks/paper/harness/contracts/build
python3 benchmarks/paper/harness/contracts/build_runner.py \
  --dtvm-build "$DTVM_BUILD" --wasmtime-capi "$WASMTIME_CAPI" \
  --boost-include "$BOOST_SOURCE_DIR" \
  --out benchmarks/paper/harness/contracts/build/contract-runner
python3 benchmarks/paper/harness/contracts/validate.py \
  --runner benchmarks/paper/harness/contracts/build/contract-runner \
  --artifacts benchmarks/paper/harness/contracts/build \
  --results benchmarks/paper/harness/contracts/build/validation.json
```

The runner embeds a runpath to the provided Wasmtime `lib/` directory; keep the
C API installation available. `build_inputs.sh` creates the Wasm files, the C
case's WAT and checksums. WABT 1.0.36 and Clang 16.0.6 were used for the
recorded run. Native reference calculations require PyCryptodome's Ethereum
Keccak; the host itself has no Python dependency.

Example individual invocation:

```bash
benchmarks/paper/harness/contracts/build/contract-runner dtvm-lazy \
  benchmarks/paper/harness/contracts/build/merkle_proof.wasm 8903c5a2 --trace
```

Choose `dtvm-interp`, `dtvm-singlepass`, `dtvm-multipass`, `dtvm-lazy`, or
`wasmtime`. `finish` returns process status 0, `revert` 2, and host/engine
errors 1. `validation.json` captures output, host-call counts, traces and
binary hashes. The 65 checks cover five engines × thirteen cases: original and
new Merkle, invalid proof, NFT IDs 0/1/2, Fibonacci, full-width arithmetic,
zero modulus, Keccak, calldata and code-copy padding, invalid selector,
out-of-bounds memory and invalid export signatures. They are functional smoke checks, not
exhaustive ABI or VM tests.

## Exploratory process-time comparison

`benchmark.py` runs independent processes in randomized within-round order.
It captures output and checks that each engine returns the same bytes and host
call counts. For example:

```bash
python3 benchmarks/paper/harness/contracts/benchmark.py \
  --runner benchmarks/paper/harness/contracts/build/contract-runner \
  --artifacts benchmarks/paper/harness/contracts/build \
  --out benchmarks/paper/harness/contracts/build/my-screen \
  --cpu 0 --rounds 31 --warmups 1 --seed 202611102
```

Use `--cases merkle-wat,generative-nft` to select a subset. The runner checks
the expected return as well as cross-engine agreement. The manifest records the
actual resolved Wasmtime shared library's path and hash, including any dynamic
loader override. Use the official 45.0.0 C API build for Wasmtime 45 comparison.

The result includes startup, runtime setup, compile, instantiation, one guest
call, native host work and teardown. It uses fresh processes with warmed file
cache; threads inherit the pinned CPU. It is not steady-state kernel time or
the original paper's repeated contract transactions. `--trace` is disabled,
but host-call counting is enabled. Both engines share host computations but
their callback and memory-validation paths differ. Wasmtime uses the 45.0.0
C API default engine configuration; no on-disk compilation cache is configured.
The Git revision in the manifest is the checkout at measurement time; separately
check that the supplied runner was actually built from that checkout.

The initial cohorts and the post-review 21-round screen and separately seeded
31-round confirmation, including hashes and every raw process sample, are
preserved under `docs/changes/2026-11-10-contract-mock-runner/evidence/`.
They use different runner binaries and are not pooled. Post-review confirmation
medians on one AMD EPYC 9V74, with one pinned logical CPU, were:

| Case | DTVM singlepass | DTVM eager multipass | DTVM lazy multipass | Wasmtime 45 |
|---|---:|---:|---:|---:|
| Merkle WAT | 31.88 ms | 73.10 ms | 45.61 ms | 50.99 ms |
| Merkle C (new case) | 33.79 ms | 43.17 ms | 40.68 ms | 41.10 ms |
| Generative NFT | 29.42 ms | 53.05 ms | 38.10 ms | 42.07 ms |
| Fibonacci(20) | 7.29 ms | 24.60 ms | 15.70 ms | 17.33 ms |

These are per-engine medians, not paired ratios. Percentile-bootstrap intervals
of the within-round ratios are in `summary.json`; confidence intervals are
pointwise and the two independent cohorts are not pooled. The Merkle and NFT
cases invoke the native crypto host thousands of times, so these values cannot
be attributed solely to Wasm execution or JIT quality. No timing conclusion
should be drawn from the correctness run with tracing enabled.
