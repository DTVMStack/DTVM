# Change: Add JIT suitability checker for EVM bytecode

## Why

EVM bytecodes containing high concentrations of RA-expensive opcodes (SHL, SHR, SAR, MUL, SIGNEXTEND) cause the greedy register allocator to exhibit superlinear (O(n^2)) compilation time, hanging for minutes or triggering OOM kills in CI. The current fallback mechanism uses a flat linear MIR estimate that cannot distinguish pathological patterns from normal contracts with similar opcode counts.

## What Changes

- Add a pattern-aware JIT suitability analysis integrated into `EVMAnalyzer::analyze()` that detects:
  - Per-block concentration of RA-expensive opcodes
  - Consecutive runs of RA-expensive opcodes (ignoring interleaved DUPs/SWAPs)
  - DUP feedback patterns (DUPn immediately followed by an RA-expensive op)
- Replace the existing `MIR_OPCODE_WEIGHT[]` table and `estimateMirInstructionCount()` in `dt_evmc_vm.cpp` with a structured `JITSuitabilityResult` from the analyzer
- Expose configurable thresholds for fallback decisions

## Impact

- Affected specs: `evm-jit`
- Affected code:
  - `src/compiler/evm_frontend/evm_analyzer.h` (extend analysis loop)
  - `src/vm/dt_evmc_vm.cpp` (replace fallback decision logic)
  - `src/CMakeLists.txt` (include path if needed)
