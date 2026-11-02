# Change: Lazy MT BG-Greedy only start/exports (demand tiering)

- **Status**: Proposed
- **Date**: 2026-11-01
- **Tier**: Light

## Overview

Stop multithread LazyJIT from background-Greedy compiling every function that is statically reachable from exports through `CallSeqMap`. Queue BG GreedyRA only for the start function and exported functions. Unexported callees stay on stubs and compile on demand (FastRA) when first called.

## Motivation

`CallSeqMap` records direct `call` targets **and** every table function whose type matches a `call_indirect`. DFS from exports therefore BG-Greedys most of libc on short-lived WASI modules. On this box, cowsay (821 internal functions) compiled **381** bodies in the background vs **173** actually demanded; wall median 767 ms vs lazy-F-ST 137 ms vs interpreter 10 ms. Echo/md5/figlet show the same compile-dominated shape.

The start function and exported entries still get background GreedyRA. This
does not guarantee Greedy code for the actual hot loop: an exported wrapper
may spend its time in an unexported helper, which remains FastRA after first
use. This is a startup/compilation policy, not hotness-based tier promotion.
Long-running workloads need throughput measurements; eager multipass is
unchanged.

## Review fixes and coverage

- Keep the old scheduling priority: start first, hinted entry next (the loader
  places it last), then the remaining exports in reverse order. The original
  forward loop queued the likely entry behind other exports on the FIFO pool.
- Remove the obsolete shared proposal-index edit when integrating current main.
- Add `lazy_entry_seeds.wat` and JIT regression tests for an unexported start,
  export aliases, direct callees, used/unused indirect table targets, repeated
  calls, and eager/serial-lazy compatibility. Publication counters provide the
  completion barrier; tests do not rely on arbitrary sleeps.

## Impact

- **Module**: `src/compiler/compiler.cpp` (`LazyJITCompiler::dispatchEntryCompileTasks`)
- **Spec**: `docs/modules/compiler/spec.md` (lazy prefetch policy)
- **Contracts**: no API change. Default `--enable-multipass-lazy` without `--disable-multipass-multithread` compiles fewer functions in the background.
- **Out of scope**: FastRA full-scan use truncation; unconstrained `i32.add`→memarg/disp fold; call-count hot-path upgrade of unexported callees.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated (`lazyJitGreedyOndemandTests`, `lazy_entry_seeds.wat`)
- [x] Module specs in `docs/modules/` updated (if affected)
- [ ] Build and tests pass
