# Next Optimization Prompt

## Goal

Continue optimizing DTVM's EVM multipass JIT after the current peephole and
short-diamond branch-lowering work.

The current branch already:

- implements EVM frontend peephole rules in
  `src/compiler/evm_frontend/evm_mir_compiler.h` and
  `src/compiler/evm_frontend/evm_mir_compiler.cpp`
- adds an x86 compare-chain peephole in
  `src/compiler/target/x86/x86_cg_peephole.cpp`
- adds a short-diamond `br_if` fallthrough optimization in
  `src/compiler/target/x86/x86lowering.cpp`

These changes materially improve `jump_around`, `memory_grow_*`, and the full
`external/total/(main|micro)` geomean, but some jump-dense microcases still
have room for improvement.

## Current Performance Snapshot

Against the same-session `fix2` baseline:

- full `external/total/(main|micro)` geomean: about `-11.4%`
- full total sum: about `-3.8%`
- `jump_around/empty`: about `-48%`
- `JUMPDEST_n0/empty`: about `-18.6%` vs `fix2`, but still about `+4.5%` worse
  than the previous movzx-aware peephole-only variant
- `loop_with_many_jumpdests/empty`: about `+2.2%` worse than the previous
  movzx-aware peephole-only variant

Latest benchmark JSON:

- `/tmp/dtvm_shortdiamond_full.json`
- comparison baseline: `/tmp/dtvm_peephole_fix2_sameenv_full.json`
- previous best before short-diamond shaping:
  `/tmp/dtvm_peephole_movzx_peephole_full.json`

## Hypothesis

The remaining opportunity is no longer in compare materialization removal
itself. The next likely bottleneck is CFG layout for jump-heavy bytecode:

- block order may still force avoidable taken branches
- `JUMPDEST`-heavy code may want a different fallthrough policy than generic
  `br_if`
- there may be more cases where conditional inversion can remove a trailing
  `jmp` without hurting other benchmarks

## Task

Investigate and optimize the remaining jump-dense regressions, especially:

- `external/total/micro/JUMPDEST_n0/empty`
- `external/total/micro/loop_with_many_jumpdests/empty`

Prefer solutions that preserve or improve:

- `jump_around/empty`
- `memory_grow_mload/by32`
- `memory_grow_mstore/by16`
- full-suite geomean

## Constraints

- Work in a new worktree, not on `main`
- Do not revert existing frontend peephole work
- Keep gas semantics unchanged
- Preserve `evmStateTests` correctness
- Use `tools/format.sh format` and `tools/format.sh check`

## Suggested Investigation Plan

1. Inspect JIT logs and final assembly for:
   - `JUMPDEST_n0`
   - `loop_with_many_jumpdests`
   - `jump_around`
2. Compare the current short-diamond branch-lowering variant against the
   previous movzx-aware peephole-only variant.
3. Focus on:
   - block ordering
   - fallthrough direction
   - removable `jcc + jmp` tails
   - whether `optimizeBranchInBlockEnd()` can safely do more
4. Only keep a change if it improves the problematic jump-heavy cases without
   giving back the large gains already achieved on `jump_around` and
   `memory_grow_*`.

## Validation

Build:

```bash
cmake -B build_perf -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DZEN_ENABLE_MULTIPASS_JIT=ON -DZEN_ENABLE_EVM=ON \
  -DZEN_ENABLE_SPEC_TEST=ON -G Ninja
cmake --build build_perf -j
```

Hotspot benchmark:

```bash
/home/abmcar/evmone-for-test-mulx-adx/build/bin/evmone-bench \
  "/home/abmcar/DTVM-evm-peephole-rules/build_perf/lib/libdtvmapi.so,mode=multipass,enable_gas_metering=true" \
  /home/abmcar/evmone-for-test-mulx-adx/test/evm-benchmarks/benchmarks \
  --benchmark_filter='^external/total/micro/(JUMPDEST_n0/empty|jump_around/empty|loop_with_many_jumpdests/empty|memory_grow_mload/(nogrow|by1|by16|by32)|memory_grow_mstore/(nogrow|by1|by16|by32)|signextend/(zero|one))$'
```

Full sweep:

```bash
/home/abmcar/evmone-for-test-mulx-adx/build/bin/evmone-bench \
  "/home/abmcar/DTVM-evm-peephole-rules/build_perf/lib/libdtvmapi.so,mode=multipass,enable_gas_metering=true" \
  /home/abmcar/evmone-for-test-mulx-adx/test/evm-benchmarks/benchmarks \
  --benchmark_filter='^external/total/(main|micro)/' \
  --benchmark_repetitions=1
```

Correctness:

```bash
./build/evmStateTests
```
