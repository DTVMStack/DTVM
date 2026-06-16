# Real-Load U256 Analysis Suite

## Summary

This change adds a real-load EVM analysis suite for DTVM. The suite uses
mainnet replay fixtures to measure three properties:

- how often U256 operands are dynamically narrow;
- how often the multipass JIT proves those operands narrow at compile time;
- which lowering paths the JIT emits for those sites.

On the persisted Cancun replay profile, **60.0% of dynamic-u64 operand-slot
mass remains statically unproven**. This is reported as
`runtime_narrow_but_static_unknown_ratio = 0.600` over 4,652 joined operand
slots. The largest gaps are associated with non-constant operand sources such
as `SLOAD`, `CALL_RET`, `MLOAD`, `CALLDATALOAD`, and prior arithmetic results.
`PUSH` operands have no static gap in this profile.

The same profile also records 4-bit limb occupancy. Execution-weighted operands
are dominated by `U64` values: `U64` accounts for 81.5%, `ZERO` for 10.5%, and
high-sparse values for 0.69%. Within non-u64 operands, high-sparse values
account for 8.7% by execution weight. This supports treating high-sparse
operands as a low-priority shape in this corpus.

The first arithmetic-only profile produced `0.652` over 2,330 joined operand
slots. The current reference profile includes arithmetic, comparison, and
bitwise consumers, and should be used for downstream decisions.

## Background

Earlier measurements showed that the performance issue was not the runtime
operand distribution alone. Real contract workloads frequently use values that
fit in `u64`, but the static `ValueRange` analysis did not prove enough of
those values to activate narrow lowering paths.

Two missing pieces made the evidence hard to use:

- the real-load corpus was assembled from ad hoc replay fixtures;
- there was no durable way to join dynamic operand widths with static JIT range
  facts.

This change provides both pieces.

## Scope

### Replay Corpus Tooling

`tests/corpus/replay/` provides the replay fixture tooling:

- `replay_to_fixture.py` converts a real transaction into a self-contained
  EEST `state_test` fixture. Its default path uses `debug_traceTransaction`
  with `prestateTracer` and `diffMode`. The `createaccesslist` path remains a
  debug-free archive fallback.
- `sample_cancun_txs.py` samples transactions across five application classes:
  `stablecoin`, `dex`, `lending`, `nft`, and `infra`.
- `build_manifest.py` emits the corpus manifest, including logical transaction
  counts, unique codehash counts, block range, stratum counts, and app class
  labels.
- `fixture_equal.py` compares fixtures by canonical semantic equality. It
  ignores JSON key order, storage map order, hex casing, and zero padding.

The current external corpus lives outside the repository:

```text
~/dtvm-perf-corpora/mainnet-replay/cancun-suite/
```

It contains 225 Cancun-era transactions from blocks 20,000,000 through
21,800,125. The fixtures have no blob transactions.

### Dual Profiling Taps

`src/evm/arith_profile.{h,cpp}` defines two profiling streams. The interpreter
limb stream is compiled only when `ZEN_ENABLE_EVM_ARITH_PROFILE=ON`, so normal
interpreter builds keep the opcode hot path unchanged. Each stream is still
controlled by an environment variable at runtime.

- `ZEN_EVM_LIMB_PROFILE` runs in interpreter mode and records dynamic operand
  limb width and limb occupancy.
- `ZEN_EVM_RANGE_PROFILE` runs in multipass JIT mode and records static
  `ValueRange`, operand source kind, lowering path, and constant flags.

Both streams use `(codehash, pc, opcode)` as the join key. The `codehash` field
is an FNV-1a 64-bit hash over the bytecode buffer, not the manifest's keccak
codehash. This is sufficient as an offline join key and avoids adding a crypto
dependency to DTVM.

### Analysis Tooling

The analysis scripts live under `tests/corpus/analysis/`:

- `range_gap_join.py` joins Stream A and Stream B and reports
  `dynamic_u64_rate`, `analyzer_proved_u64_rate`, and `static_gap` by source,
  opcode, and app class.
- `runtime_histogram.py` converts raw Stream A rows into an analysis-ready
  per-site histogram.
- `fastpath_stats.py` reports per-opcode lowering path hit rates.
- `limb_occupancy_stats.py` reports the 4-bit limb occupancy distribution.

Generated CSV and Markdown reports are intentionally ignored. They depend on
the local corpus and instrumentation run, so they should not be committed.

### Unified Runner

`tools/run_real_load_profile.py` is the entry point for capture and analysis.
It supports three workflows:

- full capture and analysis over a corpus;
- analyze-only mode over an existing `runtime-profile/` directory;
- smoke mode for local validation.

Smoke mode samples fixtures by app class and prefers `contract-call` fixtures.
The default sample count is 4 per app class. This avoids selecting only
`data-to-eoa` fixtures or contracts rejected by the JIT suitability checks,
which would make Stream B empty.

The runner writes:

```text
build/real-load-profile/latest/
  raw/
  reports/
  logs/
  summary.json
```

Only scripts and tests are tracked. Local report outputs are left under the
selected output directory.

### Synthetic Storage Benchmark Generator

`tools/gen_realistic_benchmarks.py` emits storage-I/O-heavy `evmone-bench`
fixtures. It is distinct from the replay corpus above: the contracts are
synthetic but representative of real-load character (storage-bound), not
captured transactions. It exists because the stock benchmark suite is
compute- and crypto-heavy with almost no storage operations, while mainnet
execution time is storage-I/O dominated.

It generates four fixtures:

- `defi_amm_swap` (main) — constant-product AMM swaps interleaving u128 MUL/DIV
  with reserve and trader-balance SLOAD/SSTORE;
- `storage_rw_churn` (micro) — adjacent-slot read-modify-write throughput probe;
- `sstore_hot` / `sload_hot` (micro) — isolated SSTORE / SLOAD throughput probes.

Each contract leaves its storage in a deterministic state before any value is
read back — by reseeding, or (for `sstore_hot`) by overwriting every slot — so
behaviour is identical across `evmone-bench` iterations, which reuse one host.
Each computes a value-sensitive weighted checksum over its storage round-trips
and `REVERT`s on mismatch, so `EVMC_SUCCESS` is itself the correctness gate
(the JSON bench path does not check output). Expected checksums come from an
exact integer simulation in the generator. Correctness was verified by running
each fixture under both `mode=multipass` and `mode=interpreter` with identical
`gas_used`, and by confirming that a tampered checksum produces a revert.

Like the rest of this suite, generated outputs are not committed. Materialize
them on demand into a local evmone checkout:

```bash
python3 tools/gen_realistic_benchmarks.py <evmone>/test/evm-benchmarks/benchmarks
python3 tools/gen_realistic_benchmarks.py --selftest   # generator self-check
```

These fixtures are for local benchmarking only; they are not wired into the CI
performance gate.

## Reproduction

Use the external corpus path:

```bash
python3 tools/run_real_load_profile.py \
  --analyze-only \
  --corpus ~/dtvm-perf-corpora/mainnet-replay/cancun-suite \
  --profile-dir ~/dtvm-perf-corpora/mainnet-replay/cancun-suite/runtime-profile \
  --out-dir build/real-load-profile/latest
```

Run full capture and analysis:

```bash
cmake -S . -B build \
  -DZEN_ENABLE_EVM=ON \
  -DZEN_ENABLE_LIBEVM=ON \
  -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DZEN_ENABLE_SINGLEPASS_JIT=OFF \
  -DZEN_ENABLE_EVM_ARITH_PROFILE=ON
cmake --build build --target dtvmapi
python3 tools/run_real_load_profile.py \
  --corpus ~/dtvm-perf-corpora/mainnet-replay/cancun-suite \
  --out-dir build/real-load-profile/latest
```

Run the local smoke suite:

```bash
cmake -S . -B build \
  -DZEN_ENABLE_EVM=ON \
  -DZEN_ENABLE_LIBEVM=ON \
  -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DZEN_ENABLE_SINGLEPASS_JIT=OFF \
  -DZEN_ENABLE_EVM_ARITH_PROFILE=ON
cmake --build build --target dtvmapi
python3 tools/run_real_load_profile.py \
  --suite smoke \
  --corpus ~/dtvm-perf-corpora/mainnet-replay/cancun-suite \
  --out-dir build/real-load-profile/smoke
```

The replay fixture names do not include the fork suffix. Do not pass
`-k fork_Cancun` when running this replay corpus with `evmone-statetest`.
The standard EEST Cancun subset is different; it still uses fork-qualified
test names.

The runner allows a non-zero `evmone-statetest` exit by default. The replay
fixtures are used as a profiling workload, not as the correctness gate for this
suite. Add `--strict-statetest` when the statetest exit code should be treated
as a hard failure.

## Results

The reference profile covers arithmetic, comparison, and bitwise consumers.
The headline is:

```text
runtime_narrow_but_static_unknown_ratio = 0.600
joined_operand_slots = 4652
dynamic_u64_slot_mass = 4097.2
unproven_dynamic_u64_slot_mass = 2460.2
```

### Source-Kind Gap

| source_kind | slots | dynamic_u64 | proved_u64 | static_gap |
|---|---:|---:|---:|---:|
| SLOAD | 33 | 1.000 | 0.000 | 1.000 |
| CALL_RET | 13 | 1.000 | 0.000 | 1.000 |
| OTHER | 1539 | 0.944 | 0.019 | 0.925 |
| MLOAD | 284 | 0.884 | 0.000 | 0.884 |
| PRIOR_ARITH | 343 | 0.915 | 0.035 | 0.880 |
| SHIFT | 129 | 0.698 | 0.000 | 0.698 |
| CALLDATALOAD | 200 | 0.676 | 0.000 | 0.676 |
| ENV | 135 | 0.659 | 0.000 | 0.659 |
| BITWISE | 47 | 0.489 | 0.000 | 0.489 |
| AND | 126 | 0.705 | 0.381 | 0.324 |
| COMPARE | 258 | 1.000 | 0.767 | 0.233 |
| PUSH | 1539 | 0.877 | 0.877 | 0.000 |
| KECCAK | 6 | 0.000 | 0.000 | 0.000 |

The largest gaps are in non-constant sources. This points to producer-side
source tagging and range propagation as the most direct follow-up.

### Opcode Gap

| opcode | slots | dynamic_u64 | proved_u64 | static_gap |
|---|---:|---:|---:|---:|
| SGT | 10 | 1.000 | 0.000 | 1.000 |
| MULMOD | 2 | 1.000 | 0.000 | 1.000 |
| LT | 264 | 0.914 | 0.170 | 0.744 |
| SLT | 90 | 1.000 | 0.333 | 0.667 |
| ADD | 1962 | 0.974 | 0.349 | 0.625 |
| GT | 268 | 0.959 | 0.351 | 0.608 |
| DIV | 28 | 0.643 | 0.036 | 0.607 |
| SUB | 284 | 0.799 | 0.218 | 0.581 |
| MUL | 54 | 0.870 | 0.352 | 0.519 |
| ISZERO | 227 | 0.968 | 0.476 | 0.492 |
| OR | 128 | 0.860 | 0.383 | 0.478 |
| BYTE | 12 | 0.577 | 0.167 | 0.411 |
| XOR | 10 | 0.600 | 0.200 | 0.400 |
| EQ | 506 | 0.869 | 0.486 | 0.383 |
| AND | 500 | 0.504 | 0.206 | 0.298 |
| SHL | 192 | 0.969 | 0.693 | 0.276 |
| SHR | 102 | 0.635 | 0.480 | 0.154 |
| NOT | 13 | 0.692 | 0.692 | 0.000 |

`ADD` has the largest joined population. Comparison and bitwise consumers also
show measurable gaps, so the profile is not limited to arithmetic-only sites.

### Application-Class Gap

| app_class | slots | dynamic_u64 | proved_u64 | static_gap |
|---|---:|---:|---:|---:|
| nft | 2104 | 0.912 | 0.303 | 0.608 |
| infra | 914 | 0.910 | 0.325 | 0.585 |
| unknown | 53 | 0.868 | 0.340 | 0.528 |
| dex | 469 | 0.855 | 0.433 | 0.422 |
| stablecoin | 982 | 0.831 | 0.444 | 0.387 |
| lending | 130 | 0.646 | 0.346 | 0.300 |

All seeded app classes retain a static gap in this profile. `unknown` is the
classification residue for sub-frame code and is not a seeded app class.

### Limb Occupancy

| group | execution_weighted | site_weighted |
|---|---:|---:|
| ZERO | 10.5% | 10.6% |
| U64 | 81.5% | 77.4% |
| U128-dense | 0.63% | 0.85% |
| U192-U256-dense | 6.3% | 8.7% |
| HIGH-SPARSE | 0.69% | 2.13% |
| MID-GAP | 0.29% | 0.34% |

High-sparse operands mainly appear in `SHR`, `DIV`, and `BYTE`. They are rare
for `ADD`, `MUL`, and `SHL` in this corpus.

## Persisted Runtime Profile

The persisted profile is stored outside the repository:

```text
~/dtvm-perf-corpora/mainnet-replay/cancun-suite/runtime-profile/
```

| file | rows | contents |
|---|---:|---|
| `stream_a_limb.csv` | 61,498 | Raw interpreter operand rows with `limb_width` and `limb_mask` |
| `stream_b_range.csv` | 26,984 | Raw JIT range, source, lowering-path, and constant rows |
| `site_histogram.csv` | 4,931 | Per-site Stream A histogram |
| `app_class_map.json` | 24 | FNV-1a codehash to app-class bridge |

`site_histogram.csv` is the analysis-ready form. It was checked against the raw
Stream A profile and preserves the total row count and u64 count.

Analyze-only mode reproduced the persisted profile with:

```text
fixture_count = 225
stream_a_limb = 61498
stream_b_range = 26984
runtime_narrow_but_static_unknown_ratio = 0.600462
ADD execution-weighted fast-hit = 0.603207
U64 execution occupancy = 0.815376
```

## Validation

The following checks passed for this change:

- `cmake --build build --target dtvmapi -j$(nproc)`
- `PYTHONPATH=tests/corpus/analysis:tests/corpus/replay python3 -m unittest tests.corpus.analysis.test_real_load_runner tests.corpus.analysis.test_range_gap_join tests.corpus.analysis.test_limb_occupancy_stats tests.corpus.replay.tests.test_build_manifest tests.corpus.replay.tests.test_fixture_equal`
- `python3 -m py_compile tools/run_real_load_profile.py tests/corpus/analysis/range_gap_join.py tests/corpus/analysis/fastpath_stats.py tests/corpus/analysis/limb_occupancy_stats.py tests/corpus/analysis/runtime_histogram.py tests/corpus/replay/build_manifest.py`
- `git diff --check`
- `clang-format --dry-run -Werror src/evm/arith_profile.h src/compiler/evm_frontend/evm_mir_compiler.h`
- analyze-only runner over the persisted full profile
- smoke runner over the replay corpus

The full `tools/format.sh check` command currently fails on existing unrelated
formatting violations in paths outside this change, including `src/singlepass`,
`src/platform/sgx`, `src/host/wasi`, and `src/common/libcxx`.

## Limitations

- The stream `codehash` is FNV-1a over bytecode bytes. It is not the manifest's
  keccak codehash.
- Source-kind classification comes from Stream B. Sites that are not compiled
  by the JIT do not have source-kind rows.
- Replay fixtures use the standard EEST test account as `transaction.sender`.
  The original sender remains in `pre`, but top-level `tx.origin` and
  `msg.sender` differ from mainnet. This is acceptable for operand-width
  profiling, but these fixtures are not the correctness gate.
- The taps are measurement instrumentation. They are dormant without the
  environment gates and should be treated as profiling support, not as a
  runtime feature.

## Follow-Up

The profile bounds the recoverable static range gap at 0.600 for the measured
consumer set. The next optimization work should use this suite to measure
whether source tagging and range propagation improve fast-path hit rates for
`CALLDATALOAD`, `SLOAD`, `MLOAD`, comparison results, and `AND`-mask patterns.

`OTHER` still accounts for 1,539 joined operand slots. Further producer tagging
would make the remaining gap easier to assign.
