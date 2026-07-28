# Change: EVM Linear Region Head Selection

- **Status**: Implemented
- **Date**: 2026-07-21
- **Tier**: Light

## Overview

Allow the EVM memory Linear Region planner to skip a straight-line prefix of
blocks with no memory facts and select the first block containing a direct
memory operation as the region head. Add diagnostics for candidate discovery
and conservative rejection reasons.

## Motivation

The existing planner evaluates each CFG block as a possible region head, but it
does not explicitly identify opportunities hidden behind empty CFG prefixes.
This makes `no_head_memory_op` and `too_short` telemetry difficult to interpret
and can prevent a discovered chain from being represented under its actual
first memory block.

## Impact

This change is limited to the EVM memory planning framework behind
`ZEN_ENABLE_EVM_MEMORY_PLAN_FRAMEWORK`. The selected block still emits its own
expansion precheck. No expansion is hoisted into the skipped prefix, and the
planner does not cross branches, merges, barriers, dynamic jumps, or backedges.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated
- [x] Module specs in `docs/modules/` updated (if affected)
- [x] Build and tests pass
