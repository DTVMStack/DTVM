# Change: Batch EVM runtime-stack boundary access

- **Status**: Validated
- **Date**: 2026-07-29
- **Tier**: Full

## Overview

Add a first stage of selective stack dematerialization for the EVM
multipass frontend. Non-lifted block entries load their required live-in values
with one batch address calculation and one depth update. Non-lifted exits store
their bottom-to-top logical stack with one top/size update.

Batching is the standard runtime-stack boundary lowering. Full operand-stack
SSA remains unchanged and takes priority, so batching only handles non-lifted
blocks in SSA builds and all block boundaries when SSA is disabled.

## Contract

`EVMMirBuilder` exposes three frontend-internal operations:

- `peekStackBatch(count, skipTop)` returns operands in bottom-to-top order and
  leaves runtime depth unchanged;
- `dropStackBatch(count)` updates runtime top and size once;
- `pushStackBatch(values)` stores bottom-to-top values and updates runtime top
  and size once.

Empty batches are strict no-ops. The operations do not change `EVMInstance`,
EVMC ABI, gas accounting, exception behavior, or dynamic-jump dispatch.

## Validation

Build and frontend test commands:

```bash
cmake -S . -B build-batch \
  -DCMAKE_BUILD_TYPE=Release \
  -DZEN_ENABLE_EVM=ON \
  -DZEN_ENABLE_MULTIPASS_JIT=ON \
  -DZEN_ENABLE_SINGLEPASS_JIT=OFF \
  -DZEN_ENABLE_SPEC_TEST=ON \
  -DZEN_ENABLE_EVM_STACK_SSA_LIFT=ON \
  -DZEN_ENABLE_EVM_MEMORY_PLAN_FRAMEWORK=ON \
  -DLLVM_DIR=/path/to/llvm-15/lib/cmake/llvm
cmake --build build-batch --target evmJitFrontendTests evmDifferentialTests \
  evmStateTests
./build-batch/evmJitFrontendTests
./build-batch/evmDifferentialTests
```

Before the experimental gate was removed, validation used two Release builds
from the same source revision:

- A: V111 with boundary batching disabled;
- B: V111 with boundary batching enabled.

The change was also rebuilt as V011 (SSA disabled) in both A/B modes. Results:

| Gate | Result |
| --- | --- |
| V011 frontend | A/B common suite: 123/123; B-only batch tests: 2/2 |
| V111 frontend | A/B common suite: 123/123; B-only batch tests: 2/2 |
| V011 differential | A/B: 73/73 |
| V111 differential | A/B: 73/73 |
| state tests | B: 1798/1798 |
| forced JIT-to-interpreter fallback | B: 8/8 |
| Osaka transaction-exact replay | B: 100/100, 29 code hashes |

The exact replay used the fixture-aware state-test host, which restores complete
prestate before each transaction. Its result is
`/tmp/dtvm-pr1-b-correctness-100.json` on the measurement host, SHA-256
`8c2e8bbcd6b68010f49800f963ee54dfef23ae6685e8604a73f1abbc40c50c3d`.

The synthetic 16-slot, 8-boundary stress case reduced MIR instructions from
5147 to 3131 (-39.2%) and CgIR instructions from 4128 to 2614 (-36.7%).
Production compiler observation over the 29 real code hashes recorded 7103
batch loads/drops for 22004 slots and 7383 batch stores for 26359 slots. Top
and size were each updated 14486 times, exactly once per drop or store batch.
These coverage counters were collected with the optional compiler-observation
instrumentation from PR #587; that instrumentation is intentionally not part
of this change and is not required by the optimization.

Formal Osaka performance used CPU 24, 29 unique code hashes, 12 fresh-process
cold rounds, three warmups per variant, and 100 ms hot calibration. S0 denotes
A and S1 denotes B in the result file:

| Metric | B relative to A | 95% bootstrap CI |
| --- | ---: | ---: |
| JIT compilation, geometric mean | -2.645% | [-3.202%, -2.098%] |
| Emitted code, geometric mean | -0.168% | [-0.216%, -0.122%] |
| Hot execution, geometric mean | -0.142% | [-0.375%, +0.082%] |
| Frequency-weighted hot execution | -0.243% | [-0.626%, +0.087%] |

The result is `/tmp/dtvm-pr1-ab-formal-29x12.json`, SHA-256
`c9c71d8c9ccf7b594ce9bcf28d64dacf0cc4b52f2a080055dccf80c87c6f5f6d`.
The compiler-observation result is
`/tmp/dtvm-pr1-ab-observation-29.json`, SHA-256
`f38d5d865554ea829de3fb3a00df4d705a906d786fe859bbb0e826bed0dd834e`.
Both compile/code-size and hot-execution regression gates pass.

Reproduce exact correctness and paired performance with the existing
fixture-aware replay tools:

```bash
python3 tools/run_replay_correctness.py \
  --executable build-b-v111/evmStateTests \
  --fixture-manifest /path/to/fixtures-100-v2-manifest.json \
  --fixture-dir /path/to/fixtures-100-v2 \
  --output /tmp/dtvm-pr1-b-correctness-100.json \
  --raw-dir /tmp/dtvm-pr1-b-correctness-100-raw \
  --mode multipass --revision Osaka --cpu 24

python3 tools/run_ssa_replay_exact_performance.py \
  --s0 build-a-v111/evmStateTests \
  --s1 build-b-v111/evmStateTests \
  --performance-set /path/to/performance-set/manifest.json \
  --fixture-dir /path/to/29-fixtures \
  --output /tmp/dtvm-pr1-ab-formal-29x12.json \
  --raw-output-dir /tmp/dtvm-pr1-ab-formal-29x12-raw \
  --revision Osaka --cpu 24 --rounds 12 \
  --warmup-iterations 3 --target-hot-ms 100 \
  --bootstrap-samples 10000 --seed 20260729
```

## Risks

- A wrong base offset can reverse U256 or stack-slot order. Batch tests cover
  empty, 1-, 16-, and 17-slot shapes; differential and exact replay remain
  mandatory.
- Batching reduces address and top/size maintenance but not the four limb
  loads/stores per U256 value.
- Observation counters are compile-time structural evidence and are not a
  substitute for hot-execution measurement.
