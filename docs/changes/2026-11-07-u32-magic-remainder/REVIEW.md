# PR645 review and fixes

Reviewed compiler source at3613244 on upstream main3bff8bf. No blocking semantic
error was found in the u32 quotient/remainder transform: bounds, single operand
evaluation, zero/pow2 separation, trapping-tree rejection and signed/i64 scope
remain consistent. Direct and indirect calls both use MIR kind CALL, which the
purity guard rejects. The earlier102 MIR and98 WAST validation remains applicable;
this review does not change any compiler/runtime source or benchmark binary.

## Confirmed tooling issues

1. summarize.py silently intersected differing round sets and overwrote duplicate
   (case, engine, round) records; it could also accept failed measured processes.
   This could summarize an interrupted/invalid experiment as a valid paired study.
   Shared sample_data.py now validates manifest-declared cases/engines, complete
   rounds, uniqueness, success and finite positive timings before statistics.
   Documented failed-warmup exclusions are retained. Raw and gzip logs work alike.
   The hot sign-test tool rejects zero-iteration cohorts. Valid historical outputs
   are unchanged.
2. micro_bench.py stopped enforcing its deadline after both pipes closed, then
   called an unbounded wait(). The collector now bounds the final wait and always
   kills/reaps a remaining child and closes its selector/streams. Packet/checksum
   validation remains active under python -O. Invalid literal/duplicate divisors
   are rejected before creating output files.

## Verification

- 14 regression tests pass in normal Python and python -O: truncated, duplicate,
 failed, nonfinite and missing-case data; warmup exclusion; gzip replay; CLI
 rejection; invalid divisors; successful, failing and timed-out child cleanup,
 including a child that closes both output streams before hanging.

- All 11 archived cohort CSV summaries replay byte-for-byte; the adjusted paired
 sign-test results also match. No historical timings or conclusions were changed.

- The published generator still emits the measured Wasm input byte-for-byte.

- Changes are limited to experiment tools, regression tests and this review note.

Run from repository root:

```sh
python3 docs/changes/2026-11-07-u32-magic-remainder/test_tools.py
python3 -O docs/changes/2026-11-07-u32-magic-remainder/test_tools.py
```

Historical replay checksums and regression logs are in evidence/review-*. CI
status is reported separately against the actual PR head, not inferred from
these local tool tests.
