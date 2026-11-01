# compiler Module Specification

> Directory: `src/compiler/`

## Boundaries and Responsibilities

The compiler module is responsible for DTVM's multi-pass JIT compilation pipeline, compiling **WASM** or **EVM** bytecode into x86-64 machine code.

### Scope

- **WASM frontend**: Translate WASM bytecode to dMIR (`wasm_frontend/`, `frontend/`)
- **EVM frontend**: Translate EVM bytecode to dMIR (`evm_frontend/`, `evm_compiler.*`)
- **dMIR layer**: Intermediate representation (`mir/`), supporting constants, variables, basic blocks, instructions (including EVM-specific instructions such as `EvmUmul128Instruction`)
- **CgIR layer**: Code-generation-oriented IR (`cgir/`), containing basic blocks, instructions, registers
- **MIR→CgIR lowering**: `target/x86/x86lowering*.cpp`, `cgir/lowering.h`
- **Register allocation**: FastRA (`fast_ra`) and Greedy RA (`reg_alloc_greedy`)
- **x86 backend**: Machine code generation (`target/x86/x86_mc_lowering.cpp`, `x86_mc_inst_lower.*`), ELF output
- **EVM JIT suitability analysis**: Detect RA-expensive patterns before compilation, decide whether to fall back to interpreter

### Out of Scope

- Interpreter execution (provided by `evm/`, `runtime/`)
- Singlepass JIT (located in `src/singlepass/`)
- Module loading, instance creation (provided by `runtime/`)

---

## Core Concepts

### Multi-pass Compilation Pipeline

1. **Frontend→dMIR**: `WasmMirBuilder` / `EVMMirBuilder` translate source/bytecode to `MModule` + `MFunction` (dMIR)
2. **dMIR optimization**: `MVerifier`, `MIRPeephole` (ctz/clz-eq-0, select+icmp, local algebra, unsigned pow2 `udiv`/`urem`, add-imm reassoc, constant `br_if`, entry-wide FP-const hoist), `DeadMBasicBlockElim`, re-`MVerifier`
3. **dMIR→CgIR**: `X86CgLowering` (i32 add/sub-imm → wrap-safe three-address `LEA64_32r`; cmp+`br_if` → cmp+jcc when the compare result has not already been materialized), `X86CgPeephole`
4. **Register allocation**: `FastRA` or `CgRAGreedy` + `CgRegisterCoalescer`, `CgVirtRegMap`, `CgLiveIntervals`, etc.
5. **Post-RA processing**: `PrologEpilogInserter`, `ExpandPostRAPseudos`
6. **Machine code emission**: `X86MCLowering` → ELF `.text` section
7. **Linking and memory protection**: `emitObjectBuffer`, `mprotect`

### Frontend Context

- **WasmFrontendContext**: WASM module reference, thread context
- **EVMFrontendContext**: EVM bytecode, Gas metering toggle, Gas chunk metadata, `evmc_revision`

### Compilation Entry Points

- **EagerJITCompiler**: WASM full compilation
- **LazyJITCompiler**: WASM on-demand compilation (multi-threaded)
- **EagerEVMJITCompiler**: EVM full compilation (Multipass only)
- **MIRTextJITCompiler**: Compile from MIR text (testing/debugging)

---

## External Contracts

### Upstream Dependencies

| Module | Usage |
|------|------|
| `runtime/` | `Module`, `Instance`, `EVMModule`, `CodeEntry`, `CodeMemPool` |
| `action/` | `vm_eval_stack`, `vm_eval_stack.h` (EVM stack) |
| `evm/`, `evmc/` | EVM semantics, instruction table, `evmc_opcode` |
| `common/` | `ErrorCode`, `WASMType`, `MemPool`, `ThreadPool` |
| `platform/` | `mprotect`, memory allocation |
| `utils/` | `Statistics`, `JitDumpWriter` (perf integration) |
| LLVM | `TargetMachine`, `MCContext`, `TargetInstrInfo`, `TargetRegisterInfo` |

### Downstream Consumers

| Module | Invocation |
|------|----------|
| `action/` | `performMultipassJITCompile` / `performEVMJITCompile` calls `EagerJITCompiler::compile()` / `EagerEVMJITCompiler::compile()` |
| `vm/` | Indirectly via the action layer |

---

## Invariants and Permissions

### Compilation Context Invariants

- When `CompileContext::Inited == true`, `MemPool`, `CodePtr`, `FuncOffsetMap`, etc. are in a valid state
- `EVMFrontendContext` must have `Bytecode`, `BytecodeSize`, `GasMeteringEnabled`, `GasChunkInfo` (if chunk metering is enabled) set before `compile()`

### LazyJIT stub publish monotonicity

In multithread LazyJIT, each function stub's `jmp` target is published monotonically:

- trampoline (`rel32 == 0`) → FastRA → GreedyRA
- `CompileStatus::Done` means `GreedyRACodePtrs[FuncIdx]` is the canonical compiled body
- After Done, foreground FastRA must not patch the stub; `compileFunctionOnRequest` returns the GreedyRA pointer
- FastRA may CAS-patch only from the trampoline; background GreedyRA may overwrite trampoline or FastRA
- Tear-free `xchg` of the 4-byte `rel32` does not by itself enforce this ordering
- `getForegroundCompileCount` / `getBackgroundCompileCount` count entered compile attempts (incremented at path entry, before `Done` or stub patch). An acquire load of either is not a completion barrier
- `getBackgroundPublishCount` counts completed background Greedy publications (incremented with release after canonical pointer, `Done`, and stub `xchg`). An acquire load that observes N happens-after those N publishes
- Modules with exactly one internal function skip the FastRA/background-Greedy split as a measured policy for fib-like workloads: no `ThreadPool`, on-request compile uses the configured allocator (Greedy unless `DisableMultipassGreedyRA`), and the stub is published trampoline → compiled body with unconditional `xchg`. There is no concurrent FastRA publisher. This is not a claim that no one-function module can benefit from FastRA-first tiering.

### Wasm linear-memory addressing

Wasm32 effective address is `zext64(wrap32(base)) + memarg_offset`, then
trap if `ea + access_size` exceeds memory length. `getMemoryLocation`
may fuse a **constant** wasm address with the memarg offset into a 32-bit
displacement. It must not fold `i32.add(dynamic, imm)` into that
displacement: x86-64 `[MemBase + zext(x) + (N+C)]` is not wrap-equivalent
(extra OOB when `x+C` wraps; a wrapping i32 combine of `C+N` can miss
OOB). Load/store Scale stays 1. See
`tests/wast/multipass/address_add_imm_wrap.wast`.

### dMIR Invariants

- `MBasicBlock`s in `MFunction` are connected by control flow; `MInstruction`s belong to an `MBasicBlock` or are embedded as expressions in another `MInstruction`
- `MVerifier` must pass before entering CgIR lowering
- `MIRPeephole` is function-local and deterministic: it rewrites nested
  integer expression trees and constant `br_if` terminators, and hoists
  non-zero FP constants used outside the entry block into an entry
  `dassign`. The hoist is entry-wide: it does not run loop/preheader or
  use-frequency analysis, skips `+0.0` (x86 `FLD0`), and skips an entry
  with predecessors so a backedge cannot re-execute the init. Growing
  the frame and live ranges is an unmeasured tradeoff (jacobi assembly
  has been seen to grow `0x28` → `0x58`). It must
  not fold `sdiv`/`srem`, `udiv`/`urem` by zero (wasm traps), or `ctz`/`clz`
  compares against a non-zero constant. Unsigned `udiv`/`urem` by a
  nonzero constant power of two may become `ushr`/`and`. Const-const
  `udiv`/`urem` with any nonzero divisor may fold to a constant (this
  does not require a power of two). It may reassociate i32 `add(add(x,C1),C2)`,
  canonicalize i32 `sub(x,C)` to `add(x,-C)`, and rewrite `mul` by a power
  of two to `shl`. i64 ADD/SUB must retain their carry/borrow flags for EVM ADC/SBB chains.
  Discarding a subtree requires a
  proven-pure **and nontrapping** tree (`isPureExpr` rejects load / call /
  wasm-check but not integer div/rem, `wasm_fptosi`/`wasm_fptoui`, i128
  overflow ops, or `EVM_UDIV128_BY64`; those must stay). Wasm `handleIDiv`
  assigns integer literals to temps; `foldAlgebra` recovers a same-block
  `dassign` of a constant through `dread` for **every integer BINARY**
  (not only `udiv`/`urem`) so `rem_u`/`div_u` by a
  power of two still become `and`/`ushr`. Folding a constant `br_if` must drop the
  untaken CFG edge **and** any phi incoming on the still-live target that
  came from this block. After the pass, `DeadMBasicBlockElim` may drop
  unreachable blocks and must keep live phi incoming lists aligned with
  remaining predecessors so a second `MVerifier` still holds.
  `PhiInstruction::removeIncoming` must compact operand slots against a
  fixed old-N base; decrementing `_operand_num` slides the slot window.
  `freeMem` must use `_operand_cap` (allocation width), not the live
  `_operand_num`. Pred/succ removal is swap-pop: `vector::erase` on a
  bump-allocated `CompileVector` can memmove into the LLVM ASan red zone.

- x86 i32 add/sub-immediates use `LEA64_32r` to preserve wrap32 without
  folding dynamic addends into memory displacements. i64 keeps ADD/SUB
  because EVM ADC/SBB consume their carry/borrow flags.

### EVM JIT Invariants

- Only Multipass mode is supported; Singlepass does not provide EVM JIT
- JIT suitability analysis should be performed before compilation; if it does not pass, fall back to interpreter

---

## Error Codes

From `common/errors.h`, used by the compiler module:

| Error Code | Description |
|--------|------|
| `MIRVerifyingFailed` | dMIR verification failed |
| `ObjectFileCreationFailed` | ELF object file creation failed |
| `UnexpectedObjectFileFormat` | Not ELF format |
| `ObjectFileResolvingFailed` | Cannot resolve .text section or relocations |
| `NoMatchedInstruction` | No matching target instruction |
| `MmapFailed` | JIT code memory allocation failed |

---

## Compatibility Strategy

### EVM JIT and Multipass-only

- **Multipass-only EVM JIT**: EVM bytecode is compiled only in Multipass JIT mode; if run mode is Singlepass, report an error and reject EVM JIT
- **Lazy not supported**: EVM currently supports Eager compilation only; warn and skip when Lazy is requested

### JIT Suitability Analysis

`EVMAnalyzer::analyze()` must be run before compilation to detect the following patterns and decide whether to fall back to interpreter:

| Threshold | Description |
|------|------|
| `MAX_JIT_BYTECODE_SIZE` (0x6000) | Bytecode size exceeds limit |
| `MAX_JIT_MIR_ESTIMATE` (0x50000) | Linear MIR estimate exceeds limit |
| `MAX_CONSECUTIVE_RA_EXPENSIVE` (0x3000) | Consecutive RA-expensive opcodes exceed limit |
| `MAX_BLOCK_RA_EXPENSIVE` (0x3000) | RA-expensive count in a single basic block exceeds limit |
| `MAX_DUP_FEEDBACK_PATTERN` (0x3000) | DUPn + RA-expensive pattern exceeds limit |

**RA-expensive opcode classification**: SHL (0x1b), SHR (0x1c), SAR (0x1d), MUL (0x02), SIGNEXTEND (0x0b).

### EVM Memory Plan Framework

When `ZEN_ENABLE_EVM_MEMORY_PLAN_FRAMEWORK` is enabled, the EVM frontend builds
block-aware `MemoryFacts` from `EVMAnalyzer` block ranges. A conservative
const-only CFG pass may propagate stack-entry memory addresses and compute the
minimum memory size guaranteed at each block entry. Lowering may use that entry
guarantee only to elide redundant constant-address `MLOAD`, `MSTORE`, and
`MSTORE8` expansion checks.

The memory plan framework may also build one conservative Linear Region
precheck for a single-entry, single-successor straight-line CFG chain. The
region head emits the expansion precheck at the first covered direct memory
operation, and successor blocks may reuse that guarantee only through the
existing block-entry guaranteed-byte query. Linear Region planning must not
cross branches, merges, backedges, `MSIZE`, `GAS`, host, escape, or
unknown-effect barriers. Existing block-local memory expansion plans remain
valid and are still consumed through the existing per-block lowering path.
The planner may skip a straight-line prefix of blocks with no memory facts and
select the first direct-memory block as the region head. This selection uses
only local unique-successor and unique-predecessor checks; it does not perform
dominator analysis. The precheck remains in the selected head and is never
hoisted into the skipped prefix.

Memory intervals support exact constants and conservative bounded offsets over
the same abstract stack-value base. Alias queries distinguish `NoAlias`,
`MustAlias`, `PartialAlias`, and `MayAlias`; unknown bases and overflow always
fall back. Ordered clobber queries are currently block-local and stop at every
hard barrier or CFG boundary.

Block prechecks select one maximal safe window with at least two proven direct
memory operations. The plan records explicit operation IDs, is emitted at the
first covered operation, and may cover gaps or overlapping intervals because
expansion grouping does not transform memory values. Per-operation guaranteed
bytes include proven earlier expansion in the same block.

`MemoryProofLifetimeAnalysis` separates two questions that are distinct under
EVM semantics. A successful memory operation may establish a logical minimum
extent that remains true after an opcode such as `GAS` or `MSIZE`; this permits
a later consumer to reuse the extent proof. It does not permit the compiler to
move a later expansion, gas charge, trap, log, return, or external call across
that opcode. The placement query therefore remains fail closed across
observable-order, trapping, externalization, termination, unknown-effect, and
unsafe CFG boundaries even when the logical-size proof survives.

Proof propagation uses the analyzer's complete predecessor relation. The
invocation entry starts with a zero-byte guarantee even when it has a backedge,
and blocks with incomplete dynamic-dispatch predecessors receive no cross-block
guarantee. Revision-undefined opcodes are terminating barriers. Prepared-memory
runtime helpers declare typed proof requirements and normal-success memory
effects; a helper contract is satisfied only when every required proof
component has been established. Cached host-base and memory-content proof
domains are deliberately not propagated until a lowering consumer requires
them.

Memory proof recovery is admitted and budgeted for online compilation. The
initial bytecode scan records a conservative `MemoryOpportunitySummary` and a
direct opcode-PC index. Modules without a reusable consumer opportunity skip
planner setup, while revision-invalid opcodes still retain the effect facts
needed for fail-closed lowering. Optional extent, region, dead-store, and load-
forwarding analyses are constructed only when a matching query is issued.

Guaranteed extent is recovered by a sparse demand oracle with independent
per-query and compilation-wide limits on block, operation, and CFG-edge work.
Only a completed query publishes its touched facts; incomplete CFGs, cycles,
or exhausted budgets retain the generic expansion path without a partial
proof. Repeated uncached queries may schedule a bounded full analysis, but the
promotion result becomes visible only after the full run completes. Cache
hits neither spend query budget nor trigger eager promotion.

The framework may eliminate only the write of an exact, fully overwritten
`MSTORE` or `MSTORE8`, and may forward an exact 32-byte `MSTORE` value to a
later `MLOAD`. Both transformations are block-local, require strict
must-alias/no-clobber proofs, and preserve each original opcode's gas and
expansion behavior. Constant nonzero `MCOPY` uses the checked maximum of source
and destination ends for expansion elision while retaining the original
`memmove` lowering. Zero-length `MCOPY` never expands memory.

### EVM Frontend Context and Gas

- Enable/disable Gas metering based on runtime config (`setGasMeteringEnabled`)
- Provide bytecode, gas chunk end/cost arrays for chunk-based metering
- Use register to hold gas when `ZEN_ENABLE_EVM_GAS_REGISTER` is enabled

### EVM Stack Boundary Batching

Non-lifted EVM block boundaries use batched runtime-stack access. Entry loads
use `peekStackBatch` followed by one `dropStackBatch`; exit materialization uses
one `pushStackBatch`. Batch vectors are always bottom-to-top. Empty batches emit
no MIR and do not update runtime stack state. Full stack-SSA blocks retain the
existing entry-state and phi protocol.

The runtime stack remains the complete authoritative representation in this
stage. Every non-lifted exit still writes all logical values, and dynamic
dispatch, fallback, gas, and runtime ABI behavior are unchanged.

### EVM Stack SSA Lift Safety

- `ZEN_ENABLE_EVM_STACK_SSA_LIFT` permits compatible EVM operand-stack values
  to cross basic-block boundaries as SSA state.
- A lifted merge must have one valid incoming for every final MIR predecessor,
  and all MIR phi instructions must remain contiguous at block start.
- Dynamic-jump lowering may expand one EVM predecessor PC into multiple MIR
  predecessor blocks. Until the merge representation distinguishes those MIR
  predecessors, a dynamic-jump target requiring an entry merge is non-lifted
  and uses the deterministic runtime-stack fallback.
- An unfiltered full-table dynamic dispatch is shared at module scope in both
  stack-SSA and non-SSA builds. This is sound while every runtime
  dynamic-dispatch target is non-lifted and consumes the materialized runtime
  stack. A source with a proven smaller candidate set retains a per-source
  filtered dispatch. Re-enabling lifting for runtime dynamic targets requires
  revisiting this predecessor-accounting contract before changing either
  invariant.
- Unsupported merge shapes must fall back before MIR phi construction; they
  must never emit an incomplete phi, fail module verification, or abort.

### Machine Code and Module Binding

- Machine code is written to `EVMModule::getJITCodeMemPool()` or the corresponding `Module` pool
- Entry point is the code pointer corresponding to FuncIdx 0
- Code section is protected via `mprotect(JITCode, size, PROT_READ | PROT_EXEC)`

### JIT Statistics and perf

- Compilation start/end times are recorded in `utils::StatisticPhase::JITCompilation`
- Eager multipass records `JIT functions compiled (eager): N` where `N`
  is the Runtime-lifetime sum of successfully compiled internal
  function bodies (accumulates across modules / extra compilations).
  Lazy records `JIT lazy stubs precompiled: N` the same way (stubs, not
  the resolver). Bodies actually compiled remain
  `JIT Lazy Compilation(Fg|Bg): M times`. `N` vs Fg is unused compilation
  volume (bodies/stubs), not unused-function cost. Compare them as a
  distinct-used-function census only for one module, single-thread lazy,
  no extra compilations (`--disable-multipass-multithread`).
- When `ZEN_ENABLE_LINUX_PERF` is enabled, perf JIT dump symbols (e.g., `EVMBB*`) are emitted for generated blocks

---

## Cross-References

| Dependency | Description |
|------|------|
| [evm](../evm/) | EVM semantics, instruction table, evmc_opcode |
| [runtime](../runtime/) | Module, EVMModule, CodeMemPool, Instance |
| [action](../action/) | performMultipassJITCompile, performEVMJITCompile, vm_eval_stack |
| [common](../common/) | ErrorCode, WASMType, MemPool, ThreadPool |
| [platform](../platform/) | mprotect, memory allocation |
| [utils](../utils/) | Statistics, JitDumpWriter |

| Depended by | Description |
|--------|------|
| action | performJITCompile, performEVMJITCompile invocations |
| vm-interface | EVMAnalyzer, JIT fallback decisions |

- [EVM JIT spec (archived)](../../_archive/2026-02/add-jit-suitability-checker/specs/evm-jit/spec.md): EVM JIT requirements (Multipass-only, suitability analysis, RA-expensive classification)
