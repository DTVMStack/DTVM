# Reproduction

Run from the repository root on x86-64 with GCC 14, LLVM 15 and benchmark
inputs/runtimes installed by the paper harness. Do not run builds, correctness
tests or diagnostic captures concurrently with timing. Adjust CPU affinity to
two available CPUs; the recorded environment used CPU 0 for engines/workers
and CPU 1 for the collector. Scripts retain the historical workspace paths in
manifests as provenance, not as portable installation requirements.

## Production builds

```sh
cmake -S . -B build-folding -DCMAKE_BUILD_TYPE=Release \
  -DZEN_ENABLE_ASAN=OFF -DZEN_ENABLE_SPEC_TEST=OFF \
  -DZEN_ENABLE_SINGLEPASS_JIT=ON -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DZEN_ENABLE_VIRTUAL_STACK=OFF -DLLVM_DIR=/path/to/llvm15/lib/cmake/llvm
cmake --build build-folding --target dtvm -j2
```

Use isolated checkouts/build trees for main `7eb81b0` and measured candidate
`58b0fd3`. For cold-only ablation apply `private-ablation.patch` to the
candidate and rebuild separately. Never mutate a timed executable between
rounds. Our baseline artifact is reused from an equivalent runtime source;
see REPORT.md for the explicit provenance exception and SHA256.

## Original CLI comparisons

Set `MAIN`, `CANDIDATE`, `PRIVATE`, `WASMTIME45` to absolute binary paths.

```sh
TASK=docs/changes/2026-11-07-private-tiering-load-folding
taskset -c 1 python3 "$TASK/benchmark.py" --suite wapm --rounds 7 \
  --seed 6461106 --out results-wapm \
  --variants main,combined,combined_tier,wt45 \
  --main "$MAIN" --candidate "$CANDIDATE" --private "$PRIVATE" \
  --wasmtime "$WASMTIME45" --main-commit 7eb81b0 --candidate-commit 58b0fd3
# PolyBench scout: replace suite with polybench, rounds with 1, seed with
# 6461105, variants with main,combined,wt45, add --warmups 0 and use new out.
# R31 focused cohort: --cases atax,bicg,amirali,echo,md5,pi,qr2text
# --rounds 31 --seed 6461104, default seven variants, no --suite.
# Selecting pi automatically adds the separate pi1000 input.
# syr2k R31: --suite polybench --cases syr2k --rounds 31 --seed 6461108
# --variants main,combined,wt45.
# syr2k ablation R21: --suite polybench --cases syr2k --rounds 21
# --seed 6461109 --variants main,private,combined,wt45.
```

Exact argv, cwd/stdin, input hashes, randomized order and binary hashes are
retained in each manifest. Existing harness controls WT45 cache and DTVM
lazy-G-MT settings. `_tier` appends `--enable-lazy-private-tiering` only.

## Reanalyze saved measurements

```sh
node "$TASK/analyze.mjs" "$TASK/evidence/confirm-r31"
node "$TASK/analyze.mjs" "$TASK/evidence/wapm-final-r7"
node "$TASK/analyze.mjs" "$TASK/evidence/polybench-scout-r1"
node "$TASK/analyze.mjs" "$TASK/evidence/syr2k-confirm-r31"
```

The analyzer verifies completeness, duplicate rounds, exit status and output
hash equality (except nondeterministic fortune/uuid). It writes summary.json
with paired medians and pointwise intervals. R1 intentionally has no CI.
Sam's shared nonzero warmup exit is retained/excluded. Frozen phase summaries
and raw phase samples are supplied separately; they use packet clock fields,
not the wall-only analyzer. Their generator/runner is
`docs/changes/2026-11-07-anonymous-grown-pages/phase_bench.py`;
`run_final.py` records the exact historical phase invocation.

## Native and correctness evidence

`evidence/native/` contains untimed function bytes, selected disassemblies and
PC maps for the bicg comparison. Gzip-decompress a function binary and use
`objdump -D -b binary -m i386:x86-64 FILE` to inspect it. Diagnostic build and
capture scripts are supplied for audit; they are workspace research scripts,
require the separately built sampling preload library, and are never timed
production artifacts. Do not compare their compile durations as production
performance. `native-loops.json` contains the loop census.

Compressed test logs document MIR, policy, ASAN and WAST validation. Adapt
upstream fixtures with `tests/wast/spec.patch` before configuring SPEC tests;
reverse that fixture-only patch after testing. ASAN coverage used O1 with
leak detection disabled, separate from production O3 measurements.
