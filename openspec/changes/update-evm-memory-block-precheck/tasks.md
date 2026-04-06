## 1. Scope and Eligibility

- [x] 1.1 Define the first-wave optimization envelope in `src/action/evm_bytecode_visitor.h`
  - Restrict planning to block-local direct-memory patterns that can be proven by local bytecode scan
  - Cover only `MLOAD`, `MSTORE`, and `MSTORE8`
  - Require at least two covered direct-memory ops before enabling a plan
  - Acceptance: unsupported or ambiguous blocks return an empty plan and retain the original codegen path

- [x] 1.2 Define the terminator and block-boundary behavior for the scan
  - Stop the scan at post-entry `JUMPDEST`
  - Treat `JUMP`, `JUMPI`, `RETURN`, `STOP`, `INVALID`, `REVERT`, and `SELFDESTRUCT` as block terminators
  - Acceptance: the scan does not continue into a fallthrough or successor block after a terminator

- [x] 1.3 Reject malformed immediate patterns conservatively
  - Reuse the existing bounded parsing style for `PUSH1..PUSH8`
  - Add explicit length guarding before advancing over `PUSH9..PUSH32`
  - Acceptance: truncated `PUSHn` immediates cannot produce an eligible precheck plan

## 2. Planner and Builder Integration

- [x] 2.1 Add block-entry planning in `handleBeginBlock(...)`
  - Run `analyzeConstDirectMemoryBlockPrecheck(...)` at block entry
  - Install a builder-side plan only when the scan marks the block eligible
  - Acceptance: non-eligible blocks do not change builder behavior

- [x] 2.2 Add builder-side plan storage and lifecycle management in `src/compiler/evm_frontend/evm_mir_compiler.h` and `.cpp`
  - Track whether the plan is active, emitted, and how many covered ops remain
  - Track `MaxRequiredSize` and `CoveredDirectOps`
  - Acceptance: plan state resets at block boundaries and after final covered-op consumption

- [x] 2.3 Emit one shared precheck for the first covered op
  - Lower one `expandMemoryIR(MaxRequiredSize, NoOverflow)` before the first covered direct-memory opcode
  - Reuse that precheck for later covered ops in the same block
  - Acceptance: covered ops skip their redundant per-op pre-expansion path after the shared precheck is emitted

## 3. Correctness Constraints

- [x] 3.1 Preserve existing memory expansion semantics
  - Reuse `expandMemoryIR(...)` instead of introducing a new runtime path
  - Preserve overflow trapping, max-size checks, aligned growth, and gas charging
  - Acceptance: covered blocks still execute the same memory-expansion semantics as the original path

- [x] 3.2 Keep helper-sensitive or unsupported blocks on the original path
  - Fail closed on helper barriers, unsupported opcodes, unknown addresses, or stack simulation failure
  - Acceptance: unsupported blocks compile exactly as before

- [x] 3.3 Keep condition typing aligned with the current EVM frontend
  - Represent `NoOverflow` using the same condition-value type used by existing EVM compare and branch paths
  - Acceptance: the precheck path builds cleanly in CI configurations without assuming a non-existent `I1Type`

## 4. Diagnostics and Instrumentation

- [x] 4.1 Add block-local memory diagnostics for development builds
  - Track direct-memory op counts, helper barriers, precheck hits, and expansion-related summary counters
  - Acceptance: logging builds can compare covered and uncovered blocks through summary output

- [x] 4.2 Separate diagnostics-only bookkeeping from optimization-critical state
  - Gate pure counters and block-summary logging with `ZEN_ENABLE_MULTIPASS_JIT_LOGGING`
  - Leave plan creation, plan consumption, and shared precheck emission always enabled
  - Acceptance: non-logging builds keep the optimization behavior without paying diagnostics-only bookkeeping cost

## 5. Validation

- [x] 5.1 Perform targeted build validation for the affected frontend
  - Build `evmStateTests` after the optimization and follow-up fixes
  - Acceptance: the modified frontend compiles cleanly in the local development build

- [x] 5.2 Reproduce the release-style CI compile path that previously failed
  - Configure and build a separate `Release + multipass + evmfallbacksuite` tree
  - Acceptance: the build completes after aligning `NoOverflow` with the existing EVM condition type

- [x] 5.3 Validate optimization boundary and known limitations
  - Confirm that covered constant-address direct-memory samples can use one shared precheck
  - Confirm that helper-heavy and dynamic-address cases still fall back
  - Acceptance: the documented scope matches current code behavior and known benchmark limitations

## 6. Documentation

- [x] 6.1 Rewrite `proposal.md` so it explains both optimization behavior and diagnostics scope
  - Acceptance: the proposal clearly states the problem, goals, non-goals, scope, expected benefits, and risks

- [x] 6.2 Rewrite `design.md` as a full technical design record
  - Acceptance: the design documents eligibility, scan logic, terminators, malformed-bytecode handling, `MaxRequiredSize`, shared-precheck codegen, diagnostics gating, condition typing, failure fallback, and validation strategy

- [x] 6.3 Rewrite `specs/evm-jit/spec.md` as a verifiable delta spec
  - Acceptance: requirements and scenarios describe the implemented behavior precisely enough for review and regression checking

- [x] 6.4 Sync implementation notes outside OpenSpec
  - Update `yhy_notes/P1.2_memory/week2_work.md` with review-driven fixes, CI follow-up, and validation notes
  - Acceptance: week notes reflect the current code rather than the earlier `I1Type` assumption
