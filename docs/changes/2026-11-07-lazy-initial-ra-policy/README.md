# Change: Centralize lazy initial allocator policy

- **Status**: In Progress
- **Date**: 2026-11-07
- **Tier**: Light

## Scope and plan

User-authorized extraction of existing FP/dense-word rules into
`LazyInitialRAPolicy`. Frontend supplies structured region facts; the compiler
supplies eligibility, sizes and elapsed compilation time. Preserve default
selection and publication semantics. Add optional automatic-selection guards,
then validate unit/integration behavior and measure first-call latency.

## Contract

The policy returns a decision by value (FP, word, disabled, module size,
function size, time budget, no matching loop). It owns no mutable last-decision
state. Defaults preserve the existing rules: 2048 source body bytes, no module
limit and no time budget. Zero size/time limits mean unlimited.

CLI options: `--disable-lazy-auto-greedy`,
`--lazy-auto-greedy-max-module-bytes`,
`--lazy-auto-greedy-max-function-bytes`, `--lazy-auto-greedy-budget-ms`.
These affect automatic first-demand selection in lazy MT only, not configured
Greedy in eager/serial/one-function paths or background compilation/private
promotion. The independent explicit FastRA switch retains precedence.

The module-lifetime soft budget charges lazy stub precompilation and complete
foreground compiles (MIR, allocation, emission/relocations/protection), including
failed attempts. It excludes guest execution, module loading and background
compilation. Recheck after MIR with current compile elapsed time. Admitted work
can overrun; concurrent admissions can also overrun, so this is not a hard
latency or CPU-time bound. Default unlimited mode makes no budget clock calls.
Elapsed time changes allocator scheduling only, never guest semantics.

## Validation

- [ ] Build production and lazy tests
- [ ] Existing lazy integration tests and deterministic policy boundary tests
- [ ] Format/diff review
- [ ] Separate first-call and full-process measurements against frozen main,
      previous candidate and Wasmtime 45

Compiler contracts: [compiler spec](../../modules/compiler/spec.md).
