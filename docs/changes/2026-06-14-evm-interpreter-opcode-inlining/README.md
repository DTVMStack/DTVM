# Change: Inline hot opcodes in the EVM interpreter dispatch path

- **Status**: Proposed
- **Date**: 2026-06-14
- **Tier**: Light

## Overview

The `mode=interpreter` computed-goto loop routed every opcode through the
`HANDLER_CALL` macro, which on each instruction wrote the local stack pointer
and program counter back to the frame, set the `EVMResource` thread-local
context, called the opcode handler, then reloaded the stack pointer. The handler
re-read the frame through that thread-local to index the stack.

This change inlines the pure stack opcodes directly into the dispatch loop so
they operate on the loop-local stack pointer and `Frame->Stack`, skipping the
per-instruction thread-local write and the `Frame->Sp`/`Pc` memory round-trip.
Two groups are inlined:

- Arithmetic, comparison and bitwise ops: ADD, SUB, MUL, DIV, SDIV, MOD, SMOD,
  LT, GT, SLT, SGT, EQ, AND, OR, XOR, SHL, SHR, ISZERO, NOT, CLZ, ADDMOD, MULMOD.
- Stack ops: POP, PUSH0, DUP1–16, SWAP1–16.

The inlined bodies are copied verbatim from the existing handler definitions, so
opcode semantics are unchanged. Builds with arithmetic-operand profiling enabled
keep routing the arithmetic ops through their handlers so the profiling tap
still fires.

PUSHX is deliberately left on its helper. Inlining its immediate decode and
program-counter arithmetic grows the dispatch function enough to regress
jump-heavy bytecode (PUSH→JUMP loops) through worse code layout, with no
offsetting gain. Excluding it keeps the change a uniform improvement.

## Motivation

Profiling the interpreter on snailtracer attributed 55% of self-time to the
dispatch function. A large part was per-opcode fixed overhead — the thread-local
context handoff and the stack-pointer round-trip through frame memory — paid on
every instruction even though the arithmetic and stack opcodes never call the
host or change the frame. The faster reference interpreters operate on a
register-resident stack pointer with minimal global state; this change moves the
hottest opcodes onto that pattern.

## Impact

- Affected module: `src/evm/` interpreter (`interpreter.cpp` dispatch path).
  Single file changed.
- The multipass JIT path is untouched.
- Measured `mode=interpreter` speedup (evmone-bench, same-session ping-pong,
  5 repetitions, against the pre-change baseline):

  | Benchmark | Δ |
  |---|---|
  | snailtracer | −23% |
  | sha1_shifts | −41% |
  | sha1_divs | −32% |
  | swap_math | −31% |
  | blake2b_shifts | −28% |
  | structarray_alloc | −27% |
  | weierstrudel | −22% |
  | wide_compare_u256 | −47% |

  Jump-only synthetic micro-benchmarks (JUMPDEST_n0, loop_with_many_jumpdests)
  stay within measurement noise (+2–3%).

- The interpreter is the fallback execution path; production uses the multipass
  JIT, so the production-weighted impact depends on the `mode=interpreter`
  execution share.

## Checklist

- [x] Implementation complete
- [x] Tests added/updated (existing suites cover the path; no behavior change)
- [ ] Module specs in `docs/modules/` updated (if affected) — not affected
- [x] Build and tests pass — 215 interpreter unittests, 2723 statetest
  (fork_Cancun), 223 multipass unittests pass; format clean; no new build
  warnings
