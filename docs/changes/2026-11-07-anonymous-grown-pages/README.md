# Change: Anonymous zero tail for bucket memory growth

- **Status**: Implemented
- **Date**: 2026-11-07
- **Tier**: Light

## Overview

Keep the initial file-backed data template. On first positive in-bucket growth,
reserve the unused tail as private anonymous PROT_NONE pages. Existing mprotect
exposes exactly the requested size; subsequent growth reuses the reservation.
Memory is monotonic, so no additional state or workload threshold is needed.
Preserve base, previous writes, guard permissions, other instances, retirement
and existing beyond-bucket fallback. No compiler policy/ABI change.

## Motivation and scope

Phase diagnosis and same-binary mapping controls identified cold initialization
and cleanup costs. A rejected per-growth prototype added repeated syscall cost;
the final once-only reservation fixes that negative control. Consult the
[runtime specification](../../modules/runtime/spec.md).

- [x] Implementation and memory invariants reviewed
- [x] Zero/prefix/guard/isolation/retirement/fallback tests
- [x] 24 Release and 24 ASan tests pass
- [x] 97 WAST cases pass in each of four execution modes
- [x] 31-round targets, WAPM screen/followups, FP and phase controls
- [x] Negative and alternative experiments preserved separately

[Final measurements, first-result phases, rejected alternatives and raw data](REPORT.md).
Based on merged upstream main 3cb4f2e after PR643 passed all 17 checks.
