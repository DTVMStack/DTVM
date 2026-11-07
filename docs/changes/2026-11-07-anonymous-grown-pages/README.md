# Change: Anonymous zero pages for bucket memory growth

- **Status**: In Progress
- **Date**: 2026-11-07
- **Tier**: Light

## Overview

Keep the initial bucket prefix backed by its copy-on-write data template. On
in-bucket memory.grow, replace only the newly accessible, page-aligned zero tail
with private anonymous pages, within the existing owned reservation. Preserve
base addresses, guard protection, slot accounting, data initialization and
fallback when exceeding the bucket limit. No compiler/allocator-policy changes.

## Motivation

A same-binary counterfactual disabling bucket mmap improved atax/bicg/gesummv/
trisolv cold process time by roughly 10–16%, with matching outputs. Global
bucket disabling also changes initial-data copying and is not the proposed
implementation. Phase measurements show cold matrix initialization is much
slower than repeated initialization. Test the narrower grown-tail hypothesis.

## Impact and plan

Consult [runtime memory contracts](../../modules/runtime/spec.md). Remapping is
limited to growth, uses the existing POSIX reservation and abort-on-mapping-
failure convention. Existing initial data and other instances are not remapped.
Validate zero growth, repeated growth, prefix persistence, adjacent/independent
instances, OOB/failure, bucket retirement and >32MB fallback. Then compare frozen
main, PR643, production candidate and Wasmtime45, preserving failed experiments.
PR643 itself has all 17 checks passing; this experiment is a separate branch.

- [x] Build and memory semantics tests
- [x] Existing spec suites in all engines
- [x] Production fresh-process and same-instance measurements
- [x] Independent confirmation and startup controls

The LEA and worker-count studies remain separate, unproven alternatives.

## Results

[Production comparisons, phase diagnosis, rejected alternatives and raw evidence](REPORT.md).
Four target cases improve versus merged main in31-round paired measurements.
WAPM screen negatives and independent followups are retained. ASan24 and
97 WAST cases in each of four execution modes pass. No new JIT pass is shipped.

## Refinement before publication

A no-touch 511-growth control found per-growth remapping overhead in v1.
Convert the unused tail only on first positive growth, with PROT_NONE, then
reuse it via existing mprotect. The module initial-size equality is a monotonic
memory invariant, not a workload threshold. Revalidate this final source and
retain v1 data separately.
