# Paper-bench JSON schema (`paper-bench-v1`)

One schema for **wall**, compilation diagnostics, and the legacy lazy estimate. Mode names are the Phase 1.5 set;
older TTFI/xlsx profile strings are aliases. Wasmtime/Wasmer columns are
omitted or marked `skipped` when the binary is missing — **never filled
with invented numbers**.

`phase15-v1` (wall-only) is superseded by this document. Existing wall
fields (`samples_s`, `median_s`, …) are unchanged.

## Top-level

| Field | Meaning |
|-------|---------|
| `schema_version` | `paper-bench-v1` |
| `generated_utc` | UTC stamp `YYYYMMDDTHHMMSSZ` |
| `host` | `uname`, `cpu_model`, `cpu_mhz`, `governor`, `no_turbo` |
| `config` | preset, scale, **metric**, CPU pin, binaries, `skipped_runtimes`, `mode_aliases` |
| `fairness_notes` | copied from `catalog.json` |
| `runs` | one object per (bench, runtime, mode) cell |

## `config.metric`

| Value | What is primary | DTVM `--enable-statistics` |
|-------|-----------------|----------------------------|
| `wall` (default) | process wall seconds | separate pass only if `--stats` |
| `ttfi` | collect compilation/estimate diagnostics; measured TTFI unavailable | separate instrumented pass |
| `both` | wall plus available compilation/estimate diagnostics | separate instrumented pass |

Every cell first collects wall samples without adding `--enable-statistics`.
When statistics are requested, a successful DTVM wall pass is followed by an
instrumented pass with its own warmup and repetitions. Only the first pass
populates top-level wall fields; the second supplies `statistics` and `ttfi`.
`config.statistics_separate_pass` indicates this collection policy. Wasmtime
uses its original command; any compile report is parsed from that command.

Wall **must not** be copied into `ttfi.ttfi_ms`. Total compilation time
also does not measure time to first invocation, and the average foreground
JIT cost is not the cost of the first invocation. None of the current
report formats measures that interval: `ttfi_ms` and `ttfi_source` therefore
remain `null`. Compilation time and the legacy estimate are separate fields.

## Canonical modes

| Canonical | Runtime | CLI / meaning | Aliases (old scripts) |
|-----------|---------|---------------|------------------------|
| `interp` | DTVM | `-m interpreter` | `interpreter` |
| `singlepass` | DTVM | `-m singlepass` | `sp` |
| `multipass-G-ST` | DTVM | multipass GreedyRA, **serial** | `multipass-g-st` |
| `lazy-F-ST` | DTVM | lazy FastRA serial | `lazy`, `dtvm multipass + lazy` |
| `multipass-F-ST` | DTVM | paper xlsx "dtvm multipass" (FastRA serial eager) | `multipass` |
| `lazy-G-ST` | DTVM | lazy GreedyRA serial | |
| `multipass-G-MT` | DTVM | greedy + multithread **on** | `multipass_greedy_mt` |
| `lazy-G-MT` | DTVM | lazy + greedy + MT on | `lazy_greedy_mt` |
| `cranelift-nocache` | Wasmtime | `wasmtime run -C cache=n` + `WASMTIME_CACHE=0` | `default`, `wasmtime`, `cranelift`, `nocache` |

`--dtvm-modes lazy,multipass` is accepted and stored as `lazy-F-ST`,
`multipass-F-ST`.

## Compilation diagnostics and the legacy estimate

| Field under `ttfi` | Source and meaning |
|--------------------|--------------------|
| `ttfi_ms` / `ttfi_source` | `null`; actual first-invocation latency is not measured |
| `compile_ms` | `Total compilation time: N ms (X μs)` → `X/1000` |
| `ttfi_est_ms` | legacy `load + precompile + instantiation + (fg_total / fg_count)`; requires all stages and positive count |
| `execution_ms` | `Execution N: X ms`, when emitted |
| `metric_samples` | successful repetitions emitting each numeric diagnostic |
| `ttfi_unavailable` | `not-measured` when proxy diagnostics exist, `not-instrumented` otherwise; failure/skip reasons take precedence |

Neither `compile_ms` nor `ttfi_est_ms` is measured TTFI. In particular,
foreground JIT may include functions reached much later in execution, and
multithreaded stage durations may overlap. Do not compare these proxies
against another runtime's measured first-invocation latency.

A diagnostic median is populated only when every requested repetition
succeeded and emitted that field. Partial metric coverage leaves the field
`null` and records its count; absent diagnostics do not invalidate successful
wall measurements. Stock Wasmtime without the paper compilation-report patch
has no compile report and therefore leaves these diagnostics `null`.

## `runs[]` (wall fields plus)

| Field | Meaning |
|-------|---------|
| `skipped` | `true` if the cell was not run |
| `skip_reason` | e.g. `wasmtime-not-found` |
| `median_s` / `samples_s` | wall seconds; **`null` / `[]` when skipped** |
| `ttfi` | measured-TTFI placeholders plus separate compilation/estimate diagnostics (above) |
| `statistics` | DTVM stats medians in ms, or `null` |
| `ok` | true only if warmup and all repetitions in every requested pass succeeded |
| `wall_ok` | whether the wall pass succeeded |
| `sample_exits` | wall attempt exit codes in order; timeout and launch-error entries are `null` |
| `failed_samples` / `timed_out_samples` | failed wall attempts (including launch errors/timeouts) / timed-out wall attempts |
| `timeout` | true if either pass timed out, including warmup |
| `instrumented` | DTVM statistics pass result and `command`, or `null` if not run; its wall fields are diagnostic only |

Markdown tables print `skip` for skipped cells, `fail` for real failures,
never a placeholder millisecond. Partial failures retain successful samples
and their medians in JSON for diagnosis, but the cell is `ok=false` and the
table prints `fail`. Counts exclude warmup; a failed warmup has no measured
attempts and is identified by `ttfi_unavailable=warmup-failed`.
Instrumented-pass counts, exit codes, timeout state and failure output are
stored separately under `instrumented`. Its failure also makes the parent
cell fail even when `wall_ok=true`. If the wall pass fails, the instrumented
pass is not attempted.

Process launch errors (e.g. missing loader or incompatible executable) are
recorded as failed attempts with an exception message in `output_tail`, and
remaining cells continue. Empty failure output never erases an earlier
nonempty failure diagnostic.

The process exits 1 if any executed cell failed or no cell succeeded
(including an empty plan or all runtimes skipped). Missing optional runtimes
do not fail a run when at least one cell succeeds and no executed cell fails.

## Fairness (unchanged)

| Label | Wasmtime? |
|-------|-----------|
| `same-wasm` | yes, if a Wasmtime binary exists |
| `dtvm-hostapi-only` | no |
| `different-wasm` | Wasmtime-only overflow modules (opcode `0xfc`) |

## Optional Wasmtime runner

`run.py` looks at `--wasmtime`, `$WASMTIME`, `PATH`, then
`runtimes/wasmtime-45.0.0/out/wasmtime`. If none is executable:

- default: skip Wasmtime cells, record `skipped_runtimes`, exit 0 if DTVM cells all succeeded
- `--require-wasmtime`: exit 2

Wasmer is **not** timed by this harness. If `--runtimes wasmer` is passed
and the binary is missing, that is recorded as `wasmer-not-found` with no
numbers. If a Wasmer binary exists, the harness still does not emit Wasmer
ms (`wasmer-runner-not-in-this-harness`) rather than guessing.

## Example skipped Wasmtime cell

```json
{
  "bench": "atax",
  "runtime": "wasmtime",
  "mode": "cranelift-nocache",
  "fairness": "same-wasm",
  "skipped": true,
  "skip_reason": "wasmtime-not-found",
  "median_s": null,
  "samples_s": [],
  "ttfi": {
    "ttfi_ms": null,
    "ttfi_unavailable": "wasmtime-not-found"
  }
}
```
