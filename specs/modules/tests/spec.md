# tests Module Specification

> Directory: `src/tests/` + `tests/`

## Boundaries and Responsibilities

The tests module provides DTVM **test infrastructure**, responsible for:

- **WAST spec tests**: WebAssembly spec consistency; parse `.wast`/`.json`; run `assert_return`, `assert_trap`, etc.
- **EVM Assembly unit tests**: Single-opcode EVM bytecode tests (`.easm` → `.hex` + `.expected` YAML)
- **Ethereum State tests**: Official Ethereum state transition suite (JSON pre/post, transaction execution)
- **Solidity contract tests**: End-to-end smart contract tests (compiled JSON + `test_cases.json`)
- **dMIR tests**: Intermediate representation verification (`.ir` + lit/FileCheck)
- **C API tests**: `zetaengine-c.h` interface validation
- **Evmone integration**: Evmone unit test framework integration (`ZEN_ENABLE_LIBEVM`)

This module does not include: EVM interpreter (evm), Host implementation (host), compiler implementation (compiler).

## Core Concepts

### 1. WAST Spec Tests (specUnitTests)

- **SpecTest**: Parse `.wast` to JSON; enumerate `(category, unit)`; run `module`/`action`/`assert_*` commands
- **CommandID**: `Module`, `Action`, `Register`, `AssertReturn`, `AssertTrap`, `AssertExhaustion`, `AssertMalformed`, `AssertInvalid`, `AssertUnlinkable`, `AssertUninstantiable`
- **Run mode**: Select interpreter / singlepass / multipass via `RuntimeConfig`; `specUnitTests <case> <mode>`
- **Directory**: `tests/wast/` (`spec/test/core`, `proposals`, `gas`, `exception`, `multipass`, `dwasm`, etc.)
- **Dependencies**: `wast2json` converts `.wast` to JSON; `RunSpecTests.cmake` as CTest wrapper

### 2. EVM Assembly Sample Tests

- **evmInterpTests**: Iterate `tests/evm_asm/*.hex`; validate `status`, `stack`, `memory`, `storage`, `transient_storage`, `return`, `events` per `.expected` YAML
- **Input format**: `.easm` (text instructions) converted to `.hex` by `tools/easm2bytecode.py`
- **Expected format**: YAML; supports `status` (SUCCESS/REVERT, etc.), `error_code`, `stack`, `memory`, `storage`, `transient_storage`, `return`, `events`
- **Host**: `ZenMockedEVMHost` for mock account, storage, call

### 3. Ethereum State Test Execution

- **evmStateTests**: Load JSON from `tests/evm_spec_test/state_tests/`; execute per `pre`/`env`/`transaction`/`post`
- **StateTestFixture**: `TestName`, `PreState`, `Environment`, `Transaction`, `Post`
- **Fork support**: `post` indexed by fork (Frontier~Prague); filtered by `DTVM_TEST_REVISION` env var
- **Verification**: `verifyPostState` compares state root, log hash; `verifyStateRoot`, `verifyLogsHash`
- **Setup**: `parsePreAccounts`, `parseStateTestFile`, `createTransactionFromIndex`

### 4. Test Utilities and Fixtures

- **evm_test_helpers.h**: `TempHexFile`, `addAccountToMockedHost`, `calculateLogsHash`, `verifyStateRoot`, `verifyPostState`, `mapForkToRevision`, `decimalToHex`, `padAddressTo32Bytes`
- **evm_test_fixtures.h**: `ParsedAccount`, `ParsedTransaction`, `StateTestFixture`, `ForkPostResult`, `parsePreAccounts`, `parseStateTestFile`, `findJsonFiles`
- **evm_test_host.hpp**: `ZenMockedEVMHost` (recursive Host, CALL subcalls, Gas metering, storage pre-warm, selfdestruct, etc.)
- **solidity_test_helpers.h**: `SolidityTestCase`, `SolcContractData`, `SolidityContractTestData`, `EVMTestEnvironment`, `DeployedContract`, `deployContract`, `executeContractCall`, `parseTestCaseJson`, `computeFunctionSelector`, `encodeAbiParam`
- **test_utils.h**: `findExecutableDir()` for executable directory

### 5. Solidity Contract Tests

- **solidityContractTests**: Driven by `RunSpecTests.cmake`; iterate `tests/evm_solidity/*/`
- **Structure**: Each dir has `*.sol`, `contract.json` (solc output), `test_cases.json` (function name, calldata, expected)
- **Preparation**: `tools/solc_batch_compile.sh` batch compile
- **Execution**: Deploy contract → call function → check `evmc_status_code` and return value

### 6. MIR Tests

- **Directory**: `tests/mir/*.ir`
- **Tools**: `lit` + `ircompiler`, `test_mir.sh`
- **Format**: dMIR text + FileCheck directives

### 7. C API Tests

- **cAPITests**: Use `ZenRuntimeRef`, `ZenCreateRuntime`, `ZenLoadHostModule`, `ZenCreateInstance`, etc.
- **Cases**: Load embedded WASM, register Host functions, call exported functions

### 8. Evmone Fallback Tests

- **evmFallbackExecutionTests**: Requires `ZEN_ENABLE_LIBEVM`; verify interpreter fallback on JIT exception
- **Dependency**: dtvmapi library

## External Contracts

| Dependent Module | Contract |
|------------------|----------|
| runtime | `Runtime`, `EVMInstance`, `Isolation`, `EVMModule` for execution |
| evm | `Interpreter`, `ZenMockedEVMHost`, `evmc_revision` |
| host | `evm::crypto::keccak256`, precompiled implementation |
| common | `TypedValue`, `RunMode`, `ErrorCode` |
| utils | `toHex`, `parseUint256`, `parseAddress`, `parseBytes32`, `parseHexData`, `stripHexPrefix`, RLP encoding |
| evmc | `evmc::MockedHost`, `evmc_message`, `evmc_tx_context`, `evmc_revision` |
| rapidjson | JSON parse and generation |
| yaml-cpp | EVM `.expected` parsing |
| googletest | `gtest`, `TestWithParam` |

## Invariants and Permissions

- **Determinism**: Test results independent of execution order; no host-dependent non-determinism
- **Isolation**: State isolated per test case; no shared mutable globals
- **Prerequisites**: EVM tests need `tools/easm2bytecode.sh`/`solc_batch_compile.sh`; State tests need JSON conforming to Ethereum spec
- **Build switches**: `ZEN_ENABLE_SPEC_TEST` enables test targets; `ZEN_ENABLE_EVM` for EVM; `ZEN_ENABLE_LIBEVM` for evmone integration

## Error Codes

| Error Code | Source | Description |
|------------|--------|-------------|
| Test failure | gtest | Assert failure, expectation mismatch |
| JSON parse failure | rapidjson | `HasParseError` |
| File I/O failure | evm_test_* | Temp file creation failure, dir not found |
| EVMC status | evmc | `EVMC_*` execution result |

## Compatibility Strategy

- **Fork compatibility**: State tests select `post` by `evmc_revision`; new forks need `mapForkToRevision` extension
- **Format compatibility**: EVM `.expected` YAML and State JSON follow Ethereum test suite conventions; WAST follows WebAssembly spec
- **Toolchain**: `wast2json`, `solc`, `lit` versions in `docs/start.md`, `tools/requirements.txt`

## Cross-References

- [specs/testing/README.md](../../testing/README.md) — Full testing guide
- [specs/modules/evm/spec.md](../evm/spec.md) — EVM interpreter spec
- [specs/modules/runtime/spec.md](../runtime/spec.md) — Runtime and instances
- [AGENTS.md](../../AGENTS.md) — Build and test commands
