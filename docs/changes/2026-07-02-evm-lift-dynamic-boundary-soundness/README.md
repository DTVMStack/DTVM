# Change: Harden EVM stack-shape analysis before JIT admission

- **Status**: Implemented and correctness-validated
- **Date**: 2026-07-02
- **Tier**: Full
- **Original branch base**: main `5d64911`
- **Validation base commit**: `ffc56028f68558e5a812813b0873ed46554909e7`
- **Pre-hardening source hashes**: v4 evidence `metadata/source-files.sha256`
- **Merged main parent**: `ce5f36f27f00436d2197e8a284c4ac71c4ee4283`

## Overview

The multipass JIT previously used two whole-module interpreter guards for
contracts with unresolved stack shapes. This change fixes the known lifted-stack
boundary hazards and removes both structural guards. Blocks whose absolute entry
depth remains unresolved stay non-lifted and read their operands from the runtime
stack. An unresolved entry depth therefore no longer rejects the whole module
from JIT compilation.

The previously cited block `21800002`, transaction `46` divergence was not
caused by unresolved non-lifted entry depth. The dynamic DIV/MOD lowering
branched before materializing both tree-IR operands, which could leave the
sibling branch with undefined virtual-register uses. Commit `458c5b5` fixes the
shared DIV/MOD path by materializing both operands before the branch. The
targeted replay no longer produces the erroneous storage key after that fix, so
this transaction does not support retaining the unresolved-entry interpreter
guard.

## What changed

### Lifted-stack boundaries

- Materializing exits spill a lifted logical stack from the stack bottom. This
  avoids double-counting a hidden live-in prefix in the recorded stack depth.
- Dynamic exits materialize the runtime stack before indirect dispatch.
- Blocks reachable through the runtime jump table do not use lifted entry
  state. Blocks whose entry depth came from the dynamic-region heuristic also
  remain non-lifted.
- Once the conservative CFG contains a reachable dynamic jump, every canonical
  `JUMPDEST` and its static-successor closure is marked as possibly receiving
  its absolute entry depth from runtime indirect dispatch. Those blocks remain
  non-lifted even when a separate static predecessor assigned the same block a
  concrete depth. This covers backward and out-of-region dynamic entries whose
  hidden caller frame is not represented by that static depth.
- An analyzer/code-generation mismatch raises a compilation error. The caller
  can then use the interpreter instead of terminating a Release process.

### JUMPDEST fallthrough liveness

The MIR builder creates `PostRevert` and `PostReturn` blocks as insertion
points after terminating instructions. These blocks have no live fallthrough.
The previous `JUMPDEST` handling nevertheless connected such a dead block to the
next canonical destination. This added a CFG predecessor that the analyzer had
not recorded, so shared-entry phi nodes had fewer incoming values than MIR
predecessors. MIR verification then rejected the module and execution fell back
to the interpreter.

The bytecode visitor now passes an explicit `HasLiveFallthrough` value to
`handleJumpDest`. The MIR builder adds the fallthrough edge only when that value
is true. Lifted `JUMPI` fallthroughs that enter a shared `JUMPDEST` remain live
through the existing deferred-entry path.

The current admission policy relies on these changes while omitting both
shape-based whole-module guards. A non-lifted block reads its inputs from the
runtime stack and does not require a statically resolved absolute entry depth.

The dynamic-source reachability check is intentionally a conservative CFG
over-approximation. It does not prove a `JUMPI` condition constant before
following both edges. This can disable more Lift-ON stack lifting than runtime
feasibility alone requires, but it cannot make a runtime dynamic entry use an
unproven absolute depth. A fully condition-aware pruning pass is a separate
performance follow-up and must preserve this safety property.

### Under-resolved stack shapes

After resolving entry depths, the analyzer invalidates any block whose resolved
depth cannot satisfy its own stack pops. Invalidation propagates to statically
reachable successors before entry-shape metadata, liftability, and value-range
analysis are finalized.

This invalidation does not reject the whole module. A block without a resolved
absolute entry depth remains non-lifted and uses the runtime stack at execution
time.

If range propagation still encounters producer and successor vectors with
different depths, it no longer depends on a Release assertion. The analyzer
disables lifting for the module, discards inferred narrow ranges, and resets
resolved entry slots to `U256`. This prevents unrelated stack slots from being
aligned and used by a narrow-value lowering.

Compiler errors raised while visiting EVM bytecode are propagated to the
existing compile boundary, where the module can fall back to the interpreter.

### JIT admission for unresolved non-lifted stacks

`ShouldFallbackToInterp` no longer includes
`hasUnresolvedNonLiftedDeepEntryRisk()`, and the now-unused predicate and its
reachability helper are removed. The analyzer still conservatively marks blocks
that runtime indirect dispatch may enter. Those blocks remain non-lifted, but
they no longer force the rest of the module onto the interpreter.

### Invalid constant jumps

A known constant `JUMP` or `JUMPI` destination is invalid only when it is not
the original byte position of any valid `JUMPDEST` and therefore cannot be
mapped to a canonical target. Consecutive `JUMPDEST` opcodes remain valid raw
destinations: each byte position in the run maps to the run's canonical block
entry. For `JUMPI`, an invalid constant makes only the taken edge a
bad-destination path; the fallthrough remains reachable.

Such a constant is not classified as an unknown dynamic jump, including when it
has non-zero high limbs. Only an unknown target can consult the shared target
map or expand possible dynamic reachability.

## Scope and consequences

The implementation changes the analyzer, bytecode visitor, MIR builder, module
admission, and focused regression tests. It does not change the EVMC API. The
runtime change allows modules with unresolved non-lifted entry depths to JIT.
The focused internal-call regression now requires actual JIT compilation and
checks its status, output, and ground-truth result against the interpreter.

This does not disable every interpreter path. The following independent policies
remain unchanged:

- bytecode shorter than 64 bytes executes in the interpreter; in the current
  evmone benchmark path, such modules are still eagerly JIT-compiled and the
  generated code is unused, which is a separate existing inefficiency;
- bytecode-size, MIR-size, and register-allocation complexity limits retain the
  suitability fallback that bounds compilation cost;
- compilation failure makes interpreter fallback sticky, and a module without
  installed JIT code executes in the interpreter;
- `CREATE` and `CREATE2` initcode, plus contracts created earlier in the same
  transaction, execute in the interpreter;
- profile-guided JIT executes initial calls in the interpreter until background
  compilation publishes JIT code.

## Verification

The pre-hardening validated source snapshot consists of base commit
`ffc56028f68558e5a812813b0873ed46554909e7` plus the seven modified C/C++ files
whose SHA-256 values are recorded in the v4 evidence as
`metadata/source-files.sha256`. Those hashes were unchanged after testing. The
untracked `bench-results/` directory and external EVM fixtures were not
modified. This documentation was updated after the gate and does not affect the
validated binaries. The post-review hardening below is not represented by those
v4 hashes.

For that snapshot, two fresh GCC 12 Release builds exercised stack SSA lift
disabled and enabled. Both enabled multipass, spec tests, and precompile
fallback. Each configuration ran the same focused tests:

| Test binary | Lift disabled | Lift enabled |
|---|---:|---:|
| `evmJitFrontendTests` | 45/45 | 45/45 |
| `evmRangeAnalyzerTests` | 50/50 | 50/50 |
| `evmDifferentialTests` | 54/54 | 54/54 |
| **Total** | **149/149** | **149/149** |

The combined result is **298/298**. The tests cover under-resolved-depth
invalidation, conservative range reset, dead dynamic control flow, invalid
constant jumps, backward dynamic-entry depth taint, dead `RETURN` and `REVERT`
fallthrough, shared-entry phi construction, the retained unresolved-stack
admission decision for that snapshot, and interpreter/JIT result equality
including gas.

Both builds completed without compiler errors. Each build emitted 14 compiler
warning lines, with none attributed to a modified source file. The seven
modified C/C++ files passed the repository's clang-format check, and
`git diff --check HEAD` passed. The full-repository `tools/format.sh check`
returned 123 for pre-existing formatting issues outside the change.

### Post-review hardening verification

The current worktree recompiled `evmJitFrontendTests`, `evmRangeAnalyzerTests`,
`evmDifferentialTests`, and `dtvmapi` in the existing Release configurations
with stack SSA lift disabled and enabled. Each configuration passed 50/50
frontend tests, 50/50 range-analyzer tests, and 64/64 differential tests. The
internal-call differential regression confirms that an unresolved non-lifted
block can remain on the runtime stack path while its module JIT-compiles. The
dynamic-divisor regression exercises the corrected shared general-lowering
branch through DIV.

The earlier guarded post-review snapshot produced the following project local
gate results. These counts cover the preceding boundary fixes in the listed
suites, but do not by themselves validate removal of the unresolved-entry
admission guard:

| Suite | Result |
|---|---:|
| evmone multipass unit tests | 223/223 |
| EEST state tests | 2723/2723 |
| EVM assembly tests | 209/209 |
| CTest targets | 12/12 |

`ctest` ran against the worktree's lift-disabled `build/` and passed 12/12.
The lift-enabled configuration separately ran the rebuilt JIT-dependent test
binaries. This avoids attributing the lift-disabled `ctest` result to both
configurations.

Post-review hardening also makes JIT compile failure a sticky, atomic module
fallback decision. The shared compile boundary covers eager and profile-guided
background compilation without adding a test-only failure hook. The focused
frontend and differential suites above exercise both lift configurations.

Both current incremental builds completed without compiler errors or warnings
from the changed files. The four C/C++ files changed by the admission-policy
update pass clang-format dry-runs with the configured formatter and LLVM 15,
and `git diff --check HEAD` passes. The full-repository format gate still reports
pre-existing formatting violations outside this change.

### Mainnet replay evidence

The frozen lift-disabled and lift-enabled VMs have SHA-256 values
`7da5bb68601e88eff2dbbed78c332901fab5f4e4e705e44a8acf98b029420991`
and
`c6896c1b081e8e1ed7cdea4b8a2ca70c625c5a25f2bada01b8eb0c696dddb98b`,
respectively. Each VM passed 300/300 mainnet-replay-v2 Cancun fixtures.

Both VMs also passed the frozen continuous replay of blocks
`21800000..21800099`:

| Result | Lift disabled | Lift enabled |
|---|---:|---:|
| Replay process | exit 0 | exit 0 |
| Frozen validator | PASS | PASS |
| State/proof audit | PASS | PASS |
| Blocks | 100/100 | 100/100 |
| Transactions | 14,150 | 14,150 |
| Gas | 1,825,295,016 | 1,825,295,016 |
| Final block hash | `0xaa5e1274f0125381d5a07cd4521b71dd808dd581f46587f8eb82083b1052a812` | same |

The two results match on every block number, hash, transaction count, and gas
value. Validation covers gas, receipt root, logs bloom, per-block post-state,
proof-union final state, and execution-access state. The authoritative logs
contain zero `Verifying Error`, zero `JIT compilation failed`, and zero
`lift-diag` markers. This confirms that the dead-fallthrough fix removes the
observed phi-verifier failure and its interpreter fallback from this replay
window.

The replay state is an offline stateless state rooted in a proof-backed parent
state. It is not an independent full-node state-root recomputation, and its
MDBX database is not a complete mainnet state database.

These frozen VMs predate removal of the unresolved-entry guard. Their replay
results cover the other compiler fixes within these fixtures, but not the new
admission policy.
Before `458c5b5`, block `21800002`, transaction `46` requested storage key
`0xc51e32f45511c94086ad679bd468edb3b2197074a81a0ca3446204c99d92eb57`
instead of
`0xb6a8b75ae122bf609f843157cc59a3fda6034d110435651bb7f2869d45d7817b`.
A targeted JIT execution no longer requested the wrong key after that commit.
This result is consistent with the diagnosed DIV/MOD defect, but it does not
replace a continuous replay of the current no-guard revision.

## Performance scope

This correctness gate provides no end-to-end throughput conclusion. Its replay
elapsed-time fields are excluded from performance analysis.

The hidden-boundary fixed point now uses a transition-driven work queue instead
of rescanning every block after each transition. On the same adversarial
20,003-byte analyzer probe with 4,000 chained hidden-prefix blocks, a
representative Release run fell from 462,992 us to 3,908 us while producing the
same liftability result. This isolates the analyzer regression mechanism; it is
not an application benchmark.

The CI `external/total` corpus contains 194 benchmark cases. The removed guard
matched seven unique real contracts represented by 12 cases. After removal, the
full 194/194 corpus completed and those 12 cases executed through the JIT.

For those 12 cases, a single-process cold probe increased from 0.20 seconds and
36.9 MB peak RSS with the guard to 6.00 seconds and 301.3 MB without it. CI
validation runs before the timed benchmark loop, so this cold compilation cost
is not included in the reported benchmark result. A separate eager no-guard
mainnet probe remained incomplete after 600 seconds and reached 2.44 GB peak
RSS. This is an operational cold-load cost, not a correctness failure.

PR 561 and subsequent compiler-scan optimizations require independent,
controlled A/B measurements built from explicitly frozen source snapshots.
Those measurements must use identical VM options, corpora, host controls, and
correctness checks. Synthetic benchmarks, one fixture, or one mainnet
transaction can establish a regression mechanism, but cannot be extrapolated
to aggregate mainnet performance.

## Follow-up

- Reduce cold-load compilation cost for modules newly admitted after removal of
  the unresolved-entry guard, using profile-guided JIT or caching without
  reintroducing the shape-based fallback.
- Add condition-aware pruning for provably untaken dynamic-source CFG edges,
  while retaining taint for every runtime-feasible indirect entry.
- Add the lift-enabled configuration to continuous integration so lifted-stack
  boundaries remain covered.
