# Scripts

Benchmark and table-generation scripts, grouped by experiment.

## PolyBench Wall-clock

| Script | Purpose |
|--------|---------|
| `setup_polybench_case.sh` | creates `benchmark/polybenchc` and `wapm` links under `webassembly-testsuites/case/` (run once before first use) |
| `run_polybench.sh` | correctness runtest (`dtvm` / `wasmtime` / `iwasm`) |
| `bench_polybench_timing.sh` | single-runtime wall-clock CSV (1 warmup + 3 timed) |
| `webassembly-testsuites/` | `runtest_webassembly.py` + per-runtime configs (snapshot from the same source as the paper) |

Entry document: [`../docs/POLYBENCH_REPRODUCE.md`](../docs/POLYBENCH_REPRODUCE.md)

```bash
./setup_polybench_case.sh
./run_polybench.sh dtvm
./bench_polybench_timing.sh dtvm multipass
./bench_polybench_timing.sh wasmtime default
./bench_polybench_timing.sh wasmer llvm
```

## PolyBench TTFI (DTVM lazy vs Wasmtime 45 / Wasmer 7.1 three backends)

| Script | Purpose |
|--------|---------|
| `run_polybench_ttfi_round.sh <repeats>` | one-shot flow: DTVM lazy + wasmtime45 + wasmer 7.1 (cr/sp/llvm) + merged table |
| `run_polybench_ttfi_compare.sh <runtime> <profile> <repeats> <outdir>` | single runtime |
| `build_polybench_ttfi_table.py` | merge `results.csv` into md/csv |

Entry document: [`../docs/POLYBENCH_TTFI_REPRODUCE.md`](../docs/POLYBENCH_TTFI_REPRODUCE.md)

```bash
export DTVM=$PWD/runtimes/dtvm_main/dtvm
export WASMTIME=$PWD/runtimes/wasmtime-45.0.0/out/wasmtime
export WASMER=$PWD/runtimes/wasmer-7.1.0/out/bin/wasmer
export WASMTIME_CACHE=0
./run_polybench_ttfi_round.sh 1
```

## WAPM TTFI (DTVM lazy vs Wasmtime 45 / Wasmer 7.1 three backends)

| Script | Purpose |
|--------|---------|
| `run_wapm_v45_v71_round.sh <repeats>` | one-shot flow: dtvm + wt45 + wasmer 7.1 (cr/sp/llvm) + merged table |
| `run_dtvm_wt_compile_round.sh <repeats> <outdir>` | dtvm + wasmtime, 20 cases |
| `run_wasmer_ttfi_compare.sh <repeats> <outdir> <engine>` | single wasmer backend |
| `run_wasmtime_ttfi_compare.sh` | wasmtime only |
| `build_wapm_local_table.py` | build the paper-format md/csv from logs/CSVs |
| `run_wapm_local_full_round.sh <repeats>` | paper versions (wt31 + wasmer 5.0.4, optional historical comparison) |

Entry document: [`../docs/WAPM_TTFI_REPRODUCTION.md`](../docs/WAPM_TTFI_REPRODUCTION.md)

```bash
export DTVM=/path/to/DTVM/build/dtvm
export WASMTIME=$PWD/runtimes/wasmtime-45.0.0/out/wasmtime
export WASMER=$PWD/runtimes/wasmer-7.1.0/out/bin/wasmer
export WASMTIME_CACHE=0
./run_wapm_v45_v71_round.sh 3
```

## DTVM WAPM Lazy Per-stage Statistics / TTFI Estimate

Following the paper's `avg_compile_time.py`, the inferred formula is `ttfi_est = load + precompile + instantiation + (fg_jit / fg_count)`.

| Script | Purpose |
|--------|---------|
| `run_lazy_ttfi_est.sh <repeats>` | WAPM lazy + statistics, TTFI estimate |
| `run_lazy_stats.sh` | WAPM lazy + statistics, all stages / Total |
| `run_lazy_20.sh` | WAPM lazy wall-clock (20 cases, fortune stands in for zuk) |
| `run_lazy_paper.sh` | paper-style reproduction |
| `infer_lazy_timing.py` | multi-metric inference vs the paper |
| `compare_lazy_runtime_ratios.sh` | ratio comparison |

## Missing

- [ ] the original `test_lazy.sh` wall-clock script (absent from the archive; `run_lazy_ttfi_est.sh` currently serves as the statistics-metric reproduction)
- [ ] contract benchmark runner script (the runner lives in the testbed)
- [ ] version-collection script (writes `runtimes/*/version.txt`)
