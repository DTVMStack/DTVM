# Paper-bench harness (DTVM vs Wasmtime)

One entry point for **PolyBench**, **fib**, **overflow**, and **WAPM** wall
times, with a Wasmtime column **on the same `.wasm` where that is fair**.

This does not replace the older per-suite scripts under `scripts/` (TTFI
CSV/xlsx reproduction). It adds a Phase 1.5-style JSON protocol: CPU pin,
1 warmup + N timed runs, median/min/max seconds, optional DTVM statistics.

## What is fair

| Suite | Same `.wasm` vs Wasmtime 45? | Notes |
|-------|------------------------------|-------|
| PolyBench (30) | **yes** | WASI `_start`; Wasmtime `run -C cache=n` (no `--invoke main` — these modules do not export `main`) |
| fib iterative | **yes** | `perf_test_fib_iter_*.wasm`, `--invoke test_fib_iter` |
| overflow (`non_dtvm`) | **no** (Wasmtime only) | emscripten wasm uses opcode `0xfc`; DTVM cannot load it |
| overflow (`dtvm`) | **no** (DTVM only) | `env::checked_i64_*` hostapi; paper comparison is different-wasm |
| WAPM (20, `fortune` for `zuk`) | **yes** | same argv / `--dir` / stdin; cache off |
| contracts | **out of scope** | runner lives in the contract testbed |

Wall commands never add `--enable-statistics`. With `--stats`, DTVM statistics
are collected in a separate pass with its own warmup and repetitions. Only
the uninstrumented pass populates wall comparison fields; the instrumented
pass and its command are stored under `instrumented` for diagnosis.

## Quick start

```bash
# From the DTVM repo root.
./benchmarks/paper/harness/build_dtvm.sh
./benchmarks/paper/harness/fetch_wasmtime.sh   # Wasmtime 45.0.0 into runtimes/wasmtime-45.0.0/out/

# Command construction only (no binaries required):
python3 benchmarks/paper/harness/run.py --selftest
python3 -m unittest discover -s benchmarks/paper/harness -p 'test_*.py'
python3 benchmarks/paper/harness/run.py --preset smoke --dry-run

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
| `results.json` | schema `phase15-v1` (see [SCHEMA.md](SCHEMA.md)) |
| `median-table.md` | median wall seconds, one column per runtime/mode |
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

Wasmtime **45.0.0** is the current paper pin (`VERSIONS.md`). The harness
always passes `-C cache=n` and `WASMTIME_CACHE=0`.

## Catalog

A run succeeds only if at least one cell executes and all requested
repetitions in every pass succeed. Failures and timeouts print `fail` in the
table and return exit 1; partial successful samples remain in JSON along with
failure counts and exit codes. Launch errors are recorded without aborting
the remaining cells, and silent timeouts do not erase earlier error output.
`--dtvm`/`--wasmtime` and their environment variables select an exact binary:
an invalid explicit path is an error, rather than falling back to another build.

Workload ids, argv, dirs, stdin, and fairness labels live in
[`catalog.json`](catalog.json). PolyBench cases are discovered from
`benchmarks/polybenchc/*.wasm` plus a `skip_interp` list (jacobi-2d and other
long interpreter kernels).

## Related docs

- Package overview: [`../README.md`](../README.md)
- PolyBench wall CSV (older): [`../docs/POLYBENCH_REPRODUCE.md`](../docs/POLYBENCH_REPRODUCE.md)
- fib / overflow 5-way (incl. Wasmer): [`../benchmarks/overflow/REPRODUCE_fib_overflow_5way.md`](../benchmarks/overflow/REPRODUCE_fib_overflow_5way.md)
- Change proposal: [`../../../docs/changes/2026-11-01-paper-bench-harness/README.md`](../../../docs/changes/2026-11-01-paper-bench-harness/README.md)
