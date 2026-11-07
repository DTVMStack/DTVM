# Change: Anonymous zero pages for bucket memory growth

- **Status**: Proposed
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

- [ ] Build and memory semantics tests
- [ ] Existing spec suites in all engines
- [ ] Production fresh-process and same-instance measurements
- [ ] Independent confirmation and startup controls

The LEA and worker-count studies remain separate, unproven alternatives.
