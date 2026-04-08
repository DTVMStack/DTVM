## 1. JIT Suitability Analysis in EVMAnalyzer

- [x] 1.1 Define `JITSuitabilityResult` struct in `evm_analyzer.h` with fields: `ShouldFallback`, `MirEstimate`, `RAExpensiveCount`, `MaxConsecutiveExpensive`, `MaxBlockExpensiveCount`, `DupFeedbackPatternCount`
- [x] 1.2 Add `isRAExpensiveOpcode()` helper function covering SHL, SHR, SAR, MUL, SIGNEXTEND
- [x] 1.3 Add per-opcode MIR weight table (migrated from `dt_evmc_vm.cpp`) for linear MIR estimate
- [x] 1.4 Extend `EVMAnalyzer::analyze()` loop to track: consecutive RA-expensive run length, per-block RA-expensive count, DUP feedback pattern detection, MIR estimate accumulation
- [x] 1.5 Add `shouldFallbackJIT()` method combining all thresholds into a single boolean
- [x] 1.6 Add `getJITSuitability()` accessor returning the result struct

## 2. Integration into EVMC VM Execute Path

- [x] 2.1 Include `evm_analyzer.h` from `dt_evmc_vm.cpp` (verify include paths)
- [x] 2.2 Replace `MIR_OPCODE_WEIGHT[]` table and `estimateMirInstructionCount()` with `EVMAnalyzer::analyze()` + `getJITSuitability()`
- [x] 2.3 Update fallback decision in `execute()` to use `JITSuitabilityResult::ShouldFallback`
- [x] 2.4 Add diagnostic logging for fallback triggers (opcode pattern type, counts)

## 3. Verification

- [x] 3.1 Build and verify compilation succeeds in Release mode
- [x] 3.2 Run SHL/SHR/SAR benchmark: verify pathological cases trigger fallback, normal cases do not
- [x] 3.3 Run full benchmark suite: verify no OOM, no hangs, no false-positive fallbacks on real contract benchmarks
