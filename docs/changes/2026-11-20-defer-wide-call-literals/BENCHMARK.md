# Benchmark and validation

Measured upstream main `3d6c27b` and the standalone change with GCC 14,
LLVM 15.0.6, Release O3, multipass, singlepass and WASI enabled. ASAN and EVM
were disabled locally. Wasmtime 45 uses Cranelift with the module cache
disabled. Engine processes and their workers were pinned to CPU 0 on an AMD
EPYC 9V74 machine with a 2-CPU cgroup quota. After two excluded warmups, each
round runs the variants in randomized order as fresh processes. Wall time
includes startup, compilation, guest execution and teardown. The A/A arm
reruns the same main FastRA command. Intervals are pointwise 95% bootstrap
intervals of paired per-round median ratios.

The two C fixtures preserve wide calls by compiling separate translation
units and linking without LTO. The callee consumes every constant and the
changing state. The Python integer oracle checks each invocation. Running
Binaryen `wasm-opt -O2` inlines those calls in this fixture and supplies a
negative control with the same return value. These C inputs are designed
to exercise high register pressure. In the earlier signature census of 29
canonical WAPM and PolyBench modules, the largest signature had 10 parameters.

| Input | Main singlepass | Main lazy FastRA | PR lazy FastRA | Main default lazy | PR default lazy | WT45 | PR/main FastRA [95% CI] | PR/main default lazy [95% CI] |
|---|---:|---:|---:|---:|---:|---:|---|---|
| clang-calls/run_wide24/1000000 | 36.70 | 44.20 | 38.60 | 45.52 | 38.51 | 39.63 | 0.869 [0.826, 0.897] | 0.862 [0.839, 0.902] |
| clang-calls/run_small32/1000000 | 45.30 | 62.08 | 56.24 | 63.13 | 58.25 | 55.15 | 0.906 [0.898, 0.938] | 0.922 [0.894, 0.927] |
| clang-inlined/run_wide24/1000000 | 35.68 | 37.53 | 36.69 | 37.45 | 37.23 | 37.21 | 0.975 [0.962, 0.989] | 0.996 [0.983, 1.011] |
| clang-calls/run_wide24/0 | 5.72 | 7.16 | 6.89 | 6.72 | 7.47 | 8.17 | 1.018 [0.921, 1.076] | 1.050 [0.991, 1.232] |
| base64cli | 25.17 | 111.36 | 115.33 | 109.48 | 112.34 | 499.37 | 0.996 [0.956, 1.046] | 1.006 [0.986, 1.023] |
| echo | 8.09 | 24.75 | 25.06 | 26.62 | 27.71 | 39.29 | 0.999 [0.966, 1.053] | 1.043 [0.987, 1.112] |
| md5 | 7.71 | 25.92 | 26.50 | 28.13 | 28.85 | 43.01 | 1.022 [0.980, 1.050] | 1.038 [0.996, 1.081] |
| bicg | 81.93 | 60.88 | 61.30 | 61.70 | 61.77 | 73.50 | 1.007 [0.997, 1.024] | 0.982 [0.957, 1.012] |
| atax | 88.91 | 70.08 | 67.40 | 58.53 | 58.64 | 64.04 | 0.975 [0.926, 1.014] | 1.007 [0.923, 1.096] |
| clang-calls/run_wide24/0 (101-round repeat) | 5.72 | 6.79 | 6.99 | 6.75 | 6.93 | 8.12 | 1.044 [1.008, 1.075] | 1.016 [0.983, 1.058] |

All times are in milliseconds. Eager Greedy and A/A results, fixture hashes,
commands and raw samples are in the evidence directories. The 101-round
repeat checks cold caller loading and execution with a zero-iteration loop.
The separate cohorts use independent random seeds. The standalone comparison
shows a 4.4% paired FastRA slowdown on that control, with group medians of
6.79 and 6.99 ms. A separate 101-round cohort uses the earlier experimental
binary (SHA256 recorded in the manifest) for both arms, changing only
`DTVM_RESEARCH_COMPILER_MASK` from 0 to 4. Its FastRA ratio is 0.983
[0.955, 1.021], its main A/A is 0.988 [0.955, 1.020], and its default lazy
ratio is 0.994 [0.939, 1.034]. The slowdown did not replicate with that
control. These runs do not isolate a cause for the standalone slowdown.
The two cohorts are reported independently because they use different
executables and measurement windows.

The preceding same-binary experiment provided assembly captures of a matching
24-wide-literal WAT caller. Deferral reduced RBP-relative MOVs from 38 to 12
and the caller span from 608 to 450 bytes. The 21 RSP-relative MOVs were
unchanged. See the [experimental assembly and data](https://github.com/zoowii/DTVM/blob/c31be94/docs/changes/2026-11-16-fast-ra-remat-lowering/ARGUMENT_PRESSURE_2026-11-19.md).


## Reproduction

From this report's directory, with Clang 16, LLD 16 and Binaryen 120:

```sh
mkdir /tmp/dtvm-wide-pr
clang --target=wasm32 -O2 -ffreestanding -c caller.c -o /tmp/dtvm-wide-pr/caller.o
clang --target=wasm32 -O2 -ffreestanding -c callee.c -o /tmp/dtvm-wide-pr/callee.o
wasm-ld --no-entry --export=run_wide24 --export=run_small32 /tmp/dtvm-wide-pr/caller.o /tmp/dtvm-wide-pr/callee.o -o /tmp/dtvm-wide-pr/clang-calls.wasm
wasm-opt -O2 /tmp/dtvm-wide-pr/clang-calls.wasm -o /tmp/dtvm-wide-pr/clang-inlined.wasm
python3 benchmark.py --main /path/main/dtvm --candidate /path/pr/dtvm --wasmtime /path/wasmtime45 --inputs /tmp/dtvm-wide-pr --out /tmp/wide-r31
```

Use `--only zero-calls --seed 6542002 --rounds 101` with a separate output
directory for the zero-iteration repeat. The WAST fixture covers direct and
indirect calls, mixed integer/floating-point argument classes and out-of-bounds
traps during argument evaluation. Local validation executes its 11 assertions
on Wasmtime 45 and on main and candidate in four modes each.
