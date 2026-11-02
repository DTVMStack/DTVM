# Paper-bench JSON schema (`phase15-v1`)

The harness writes one JSON object per run to `results.json`. Units and
mode names match the Phase 1.5 measured notes: wall time in **seconds**,
`--enable-statistics` breakdowns in **milliseconds**.

## Top-level

| Field | Meaning |
|-------|---------|
| `schema_version` | Always `phase15-v1` |
| `generated_utc` | UTC stamp `YYYYMMDDTHHMMSSZ` |
| `host` | `uname`, `cpu_model`, `cpu_mhz`, `governor`, `no_turbo` |
| `config` | preset, scale, CPU pin, warmup/repeats, binary paths, modes |
| `fairness_notes` | copied from `catalog.json` |
| `runs` | one object per (bench, runtime, mode) cell |

## `config`

| Field | Meaning |
|-------|---------|
| `preset` | `smoke` / `phase15` / `polybench` / `fib` / `overflow` / `wapm` / `all` |
| `scale` | `dev` (1e6 fib/overflow iters) or `paper` (500M / 100M) |
| `cpu` | `taskset -c` index, or `null` if pinning disabled |
| `warmup` | discarded launches (default 1) |
| `repeats` | timed launches; median/min/max over **successful** samples |
| `stats` / `statistics_separate_pass` | whether a separate DTVM instrumented pass was requested; wall samples never add statistics |
| `dtvm_modes` | see mode table below |

## Mode names

| Mode | Runtime | CLI |
|------|---------|-----|
| `interp` | DTVM | `-m interpreter` |
| `singlepass` | DTVM | `-m singlepass` |
| `multipass-G-ST` | DTVM | `-m multipass --disable-multipass-multithread` (GreedyRA default, serial) |
| `lazy-F-ST` | DTVM | `-m multipass --enable-multipass-lazy --disable-multipass-greedyra --disable-multipass-multithread` |
| `multipass-F-ST` | DTVM | paper xlsx "dtvm multipass": greedy off, serial, eager |
| `lazy-G-ST` | DTVM | lazy + GreedyRA, serial |
| `cranelift-nocache` | Wasmtime | `wasmtime run -C cache=n` plus `WASMTIME_CACHE=0` |

Default matrix is the Phase 1.5 set: `interp`, `singlepass`, `multipass-G-ST`, `lazy-F-ST`, plus Wasmtime `cranelift-nocache`. Pass `--paper-modes` for the xlsx pair.

## `runs[]`

| Field | Meaning |
|-------|---------|
| `bench` | catalog id (`atax`, `fib_iter_dev`, `figlet`, …) |
| `suite` | `polybench` / `fib` / `overflow` / `wapm` |
| `wasm` | path relative to `benchmarks/paper/` |
| `fairness` | `same-wasm` or `dtvm-hostapi-only` |
| `runtime` | `dtvm` or `wasmtime` |
| `mode` | see table |
| `command` | argv actually executed (including `taskset` if pinned) |
| `cwd` | working directory (WAPM cases run in `benchmarks/wapm/`) |
| `ok` | warmup and every measured repetition in every requested pass succeeded |
| `wall_ok` | whether the uninstrumented wall pass succeeded |
| `exit` | last process exit code |
| `sample_exits` | wall attempt exit codes in order; timeout and launch-error entries are `null` |
| `failed_samples` / `timed_out_samples` | failed wall attempts (including launch errors/timeouts) / timed-out wall attempts |
| `timeout` | whether either pass timed out, including warmup |
| `samples_s` | successful wall samples, seconds |
| `median_s` / `min_s` / `max_s` | over `samples_s`; `null` if none succeeded |
| `statistics` | DTVM `--enable-statistics` medians in ms, or `null` |
| `instrumented` | separate statistics pass result and command, or `null` if not run; its wall values are diagnostic only |

Failed warmups have no measured attempts. If the wall pass fails, the
instrumented pass is not attempted. If only the instrumented pass fails,
`wall_ok=true` but `ok=false`, and the table still prints `fail`. Successful
partial samples are retained only for diagnosis. Counts exclude warmup.

Process launch exceptions are recorded in `output_tail`; remaining cells
continue. Empty failure output never erases the last nonempty diagnostic.
Any failed cell, or a run without successful cells (including an empty
execution plan), returns exit 1.

Wall time **includes** process startup, JIT, execution, and teardown. It is
**not** the paper xlsx Compile-only subcolumn (see `docs/XLSX_FORMAT.md`).

## Fairness

| Label | Wasmtime? | Why |
|-------|-----------|-----|
| `same-wasm` | yes | identical `.wasm`, equivalent entry/args/dir/stdin; Wasmtime cache off |
| `dtvm-hostapi-only` | no | DTVM `checked_i64_*` host imports (`overflow_dtvm_*`) |
| `different-wasm` | DTVM cannot load | Wasmtime overflow modules use opcode `0xfc` / bulk-memory; paper overflow is different-wasm by construction |

`fortune` stands in for the paper WAPM row `zuk`, matching `scripts/run_lazy_20.sh`.

## Example cell

```json
{
  "bench": "atax",
  "suite": "polybench",
  "wasm": "benchmarks/polybenchc/atax.wasm",
  "fairness": "same-wasm",
  "runtime": "dtvm",
  "mode": "multipass-G-ST",
  "samples_s": [0.121, 0.118, 0.119],
  "median_s": 0.119,
  "min_s": 0.118,
  "max_s": 0.121,
  "statistics": {
    "jit_compilation_ms": 87.0,
    "execution_ms": 72.1,
    "total_ms": 159.6
  }
}
```
