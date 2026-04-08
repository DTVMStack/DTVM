# Implementation Tasks

## 1. Interpreter Implementation
- [x] 1.1 Add CLZ handler definition in `src/evm/opcode_handlers.h` using `DEFINE_UNARY_OP` macro with `intx::clz`
- [x] 1.2 Add CLZ gas cost calculation in `src/evm/opcode_handlers.cpp` (5 gas per EIP-7939)
- [x] 1.3 Integrate CLZ handler into interpreter dispatch table with Osaka revision check

**Validation**: Run existing CLZ unit tests (`src/unittests/evm_eip7939_clz_test.cpp`) in interpreter mode

## 2. JIT Implementation
- [x] 2.1 Add CLZ runtime function declaration in `src/compiler/evm_frontend/evm_imported.h`
- [x] 2.2 Add CLZ runtime function implementation in `src/compiler/evm_frontend/evm_imported.cpp` using `intx::clz`
- [x] 2.3 Add CLZ case in `src/action/evm_bytecode_visitor.h` switch statement
- [x] 2.4 Add `handleClz` method declaration in `src/compiler/evm_frontend/evm_mir_compiler.h`
- [x] 2.5 Add `handleClz` method implementation in `src/compiler/evm_frontend/evm_mir_compiler.cpp` using `callRuntime`
- [x] 2.6 Add CLZ stack height update in `src/compiler/evm_frontend/evm_analyzer.h`

**Validation**: Run existing CLZ unit tests in JIT mode

## 3. EVM Assembly Tests
- [x] 3.1 Add `tests/evm_asm/clz.easm` - CLZ with input 1 (expects 255)
- [x] 3.2 Add `tests/evm_asm/clz_zero.easm` - CLZ with input 0 (expects 256)
- [x] 3.3 Add `tests/evm_asm/clz_max.easm` - CLZ with max value (expects 0)

**Validation**: Run easm tests with Osaka revision

## 4. CLI EVM Revision Support
- [x] 4.1 Add `--evm-revision` CLI option in `src/cli/dtvm.cpp`
- [x] 4.2 Pass revision to `loadEVMModule` when specified

**Validation**: Run `dtvm --format evm --evm-revision osaka <bytecode>` to test CLZ opcode

## 5. Integration Verification
- [x] 5.1 Verify revision-based opcode availability (undefined before Osaka)
- [x] 5.2 Run full EVM test suite to ensure no regressions

**Validation**: All EVM spec tests pass

## Dependencies
- Task 2.x depends on Task 1.x completion (interpreter provides reference behavior)
- Tasks 2.1-2.5 can be developed in parallel
- Task 3.x (easm tests) can be developed in parallel with Task 1.x and 2.x

## Notes
- CLZ opcode value: 0x1e
- Gas cost: 5 (VERYLOW tier)
- Stack: 1 input, 1 output (unary operation)
- Available from: EVMC_OSAKA revision
