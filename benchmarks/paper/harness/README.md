# Paper-bench harness (DTVM vs Wasmtime)

One entry point for **PolyBench**, **fib**, **overflow**, and **WAPM** wall
times, with a Wasmtime column **on the same `.wasm` where that is fair**.

This does not replace the older per-suite scripts under `scripts/` (CSV
xlsx dumps). Wall and compilation diagnostics share schema `paper-bench-v1` and the same
mode names (`lazy` → `lazy-F-ST`, …). Wasmtime runs **only if a binary is
found**; otherwise those cells are `skipped` with no invented numbers.

## What is fair

| Suite | Same `.wasm` vs Wasmtime 45? | Notes |
|-------|------------------------------|-------|
| PolyBench (30) | **yes** | WASI `_start`; Wasmtime `run -C cache=n` (no `--invoke main` — these modules do not export `main`) |
| fib iterative | **yes** | `perf_test_fib_iter_*.wasm`, `--invoke test_fib_iter` |
| overflow (`non_dtvm`) | **no** (Wasmtime only) | emscripten wasm uses opcode `0xfc`; DTVM cannot load it |
| overflow (`dtvm`) | **no** (DTVM only) | `env::checked_i64_*` hostapi; paper comparison is different-wasm |
| WAPM (20, `fortune` for `zuk`) | **yes** | same argv / `--dir` / stdin; cache off |
| contracts | **out of scope** | runner lives in the contract testbed |

Wall samples never add `--enable-statistics`: its timers and logging would
bias comparisons with Wasmtime. `--stats` and `--metric ttfi|both` collect
DTVM statistics/TTFI in a separate pass, with its own warmup and repetitions.
This adds another set of DTVM invocations; instrumented wall times are kept
only as diagnostics under `instrumented`, outside the wall comparison table.

## Quick start

```bash
# From the DTVM repo root.
./benchmarks/paper/harness/build_dtvm.sh
./benchmarks/paper/harness/fetch_wasmtime.sh   # Wasmtime 45.0.0 into runtimes/wasmtime-45.0.0/out/

# Command construction only (no binaries required):
python3 benchmarks/paper/harness/run.py --selftest
python3 benchmarks/paper/harness/run.py --preset smoke --dry-run
python3 -m unittest discover -s benchmarks/paper/harness -p 'test_*.py'

# Tiny measured matrix (atax, fib 1e6, overflow builtin 1e6, figlet):
./benchmarks/paper/harness/smoke.sh
```

Phase 1.5 subset (fib 1e6, atax, jacobi-2d, overflow DTVM-host 1e6, figlet):

```bash
python3 benchmarks/paper/harness/run.py --preset phase15 --repeats 3 --cpu 0
```

Paper-scale fib (500M) + overflow (100M), same-wasm vs Wasmtime:

```bash
python3 benchmarks/paper/harness/run.py --preset fib --scale paper --repeats 5
python3 benchmarks/paper/harness/run.py --preset overflow --scale paper --repeats 5
```

Full PolyBench / WAPM (hours if interp is left on):

```bash
python3 benchmarks/paper/harness/run.py --preset polybench --dtvm-modes singlepass,multipass-G-ST,lazy-F-ST
python3 benchmarks/paper/harness/run.py --preset wapm --dtvm-modes singlepass,lazy-F-ST
```

Paper xlsx DTVM flags (`multipass-F-ST` + `lazy-F-ST`) instead of Phase 1.5:

```bash
python3 benchmarks/paper/harness/run.py --preset polybench --paper-modes --runtimes dtvm,wasmtime
```

## Outputs

Default directory: `benchmarks/paper/raw_data/harness/<preset>_<UTC>/` (gitignored).

| File | Contents |
|------|----------|
| `results.json` | schema `paper-bench-v1` (see [SCHEMA.md](SCHEMA.md)) |
| `median-table.md` | median wall seconds; `skip` if Wasmtime/Wasmer missing |
| `commands.json` | `--dry-run` argv dump |

## Environment

| Variable / flag | Default |
|-----------------|---------|
| `--dtvm` / `$DTVM` | `build-paper-bench/dtvm`, then `build/dtvm`, then `runtimes/dtvm_main/dtvm` |
| `--wasmtime` / `$WASMTIME` | `runtimes/wasmtime-45.0.0/out/wasmtime`, then `PATH` |
| `--cpu` | `0` (`taskset -c`; pass `-1` to disable) |
| `--warmup` / `--repeats` | `1` / `3` |
| `--timeout` | `600` seconds per process |
| `--stats` | off (when requested, a separate DTVM statistics pass) |
| `--scale` | `dev` |

DTVM must be a **Release** build with singlepass + multipass. Overflow
`overflow_dtvm_*` also needs `-DZEN_ENABLE_CHECKED_ARITHMETIC=ON`.
`build_dtvm.sh` turns both on.

Wasmtime **45.0.0** is the current paper pin (`VERSIONS.md`). When present,
the harness passes `-C cache=n` and `WASMTIME_CACHE=0`. When absent, it
skips (use `--require-wasmtime` to fail). TTFI (`--metric ttfi|both`) is
a legacy CLI name for collecting compilation/estimate diagnostics.
`compile_ms` comes from the compilation report and `ttfi_est_ms` from complete
DTVM lazy statistics. Actual first-invocation latency is not measured, so
`ttfi_ms` stays null. None of these fields falls back to wall time.

A run succeeds only when at least one cell executes successfully and every
executed cell completes all requested repetitions. Partial failures and
timeouts produce `fail` in the table and exit 1; successful samples remain
in JSON alongside failure counts and exit codes. If all runtimes are skipped,
the harness also exits 1. Missing Wasmtime remains optional when DTVM succeeds.
Both passes must succeed when statistics are requested. Launch errors are
recorded in the results and do not abort subsequent cells. Failure logs are
preserved even if a later failed attempt produces no output.
An explicit `--dtvm` or `$DTVM` path must be executable; it never silently
falls back to another build. Explicit Wasmtime paths likewise never fall
back, but missing Wasmtime follows the optional-runtime skip policy.

```bash
# DTVM-only is valid when Wasmtime is not installed:
python3 benchmarks/paper/harness/run.py --preset smoke --runtimes dtvm
# Compilation/estimate diagnostics + wall, same catalog:
python3 benchmarks/paper/harness/run.py --preset wapm --metric both --dtvm-modes lazy
```

## Catalog

Workload ids, argv, dirs, stdin, and fairness labels live in
[`catalog.json`](catalog.json). PolyBench cases are discovered from
`benchmarks/polybenchc/*.wasm` plus a `skip_interp` list (jacobi-2d and other
long interpreter kernels).

## Related docs

- Package overview: [`../README.md`](../README.md)
- PolyBench wall CSV (older): [`../docs/POLYBENCH_REPRODUCE.md`](../docs/POLYBENCH_REPRODUCE.md)
- fib / overflow 5-way (incl. Wasmer): [`../benchmarks/overflow/REPRODUCE_fib_overflow_5way.md`](../benchmarks/overflow/REPRODUCE_fib_overflow_5way.md)
- Change proposals: [`../../../docs/changes/2026-11-01-paper-bench-harness/README.md`](../../../docs/changes/2026-11-01-paper-bench-harness/README.md), [`../../../docs/changes/2026-11-01-paper-bench-schema/README.md`](../../../docs/changes/2026-11-01-paper-bench-schema/README.md)
