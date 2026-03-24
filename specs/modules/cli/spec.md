# cli Module Specification

> Directory: `src/cli/`

## Boundaries and Responsibilities

The cli module is DTVM's **command-line entry point**, providing single-process, single-file WASM/EVM execution.

**Core responsibilities**:

- **Command-line parsing**: Use CLI11 to parse input file, run mode, Gas limit, log level, and other options
- **Runtime creation**: Create WASM or EVM `Runtime` according to `RuntimeConfig`
- **Module loading and execution**: Load WASM/EVM module, create isolation and instance, invoke entry function or main
- **Host module assembly**: Optionally load built-in host modules such as WASI, env, evmabimock
- **State persistence (EVM)**: Support `--load-state` / `--save-state` for EVM MockedHost state read/write
- **Benchmarking**: Support `--num-extra-compilations` / `--num-extra-executions` for extra compilation/execution to measure performance

**Excluded from scope**:

- Implementation details of the parsing library (CLI11)
- `Runtime`, `Module`, `Instance` etc. defined by the runtime module
- EVM Host implementation provided by `tests/evm_test_host.hpp` and the evm module

## Core Concepts

| Concept | Description |
|---------|-------------|
| **INPUT_FILE** | Required positional argument; WASM or EVM bytecode file path |
| **Run mode** | `interpreter`, `singlepass` (WASM only), `multipass`; maps to `RunMode` |
| **Input format** | `wasm` or `evm`; maps to `InputFormat`; decides WASM vs EVM flow |
| **Entry invocation** | If `--function` specified, invoke that function; otherwise WASM main; EVM mode: contract deploy or call |
| **EVM message** | `--deploy` uses `EVMC_CREATE`; otherwise `EVMC_CALL`; `--contract-address`, `--sender`, `--calldata` used to construct `evmc_message` |
| **exitMain** | Unified exit logic: output statistics, stop Profiler (if enabled), return exit code |

## External Contracts

### Dependent Runtime APIs

```cpp
// Create runtime
std::unique_ptr<Runtime> Runtime::newRuntime(RuntimeConfig);
std::unique_ptr<Runtime> Runtime::newEVMRuntime(RuntimeConfig, evmc::Host*);  // ZEN_ENABLE_EVM

// WASM flow
MayBe<Module*> loadModule(Filename, EntryHint);
bool unloadModule(Module*);
Isolation* createManagedIsolation();
MayBe<Instance*> Iso->createInstance(Module&, GasLimit);
bool callWasmMain(Instance&, Results);
bool callWasmFunction(Instance&, FuncName, Args, Results);
bool Iso->deleteInstance(Instance*);
bool deleteManagedIsolation(Isolation*);

// EVM flow (ZEN_ENABLE_EVM)
MayBe<EVMModule*> loadEVMModule(Filename, evmc_revision);
bool unloadEVMModule(EVMModule*);
MayBe<EVMInstance*> Iso->createEVMInstance(EVMModule&, GasLimit);
void callEVMMain(EVMInstance&, evmc_message, evmc::Result&);
bool Iso->deleteEVMInstance(EVMInstance*);
```

### Dependent Utility APIs

```cpp
// zen::utils
std::optional<std::vector<uint8_t>> fromHex(std::string_view);
std::string toHex(uint8_t*, size_t);
evmc::address parseAddress(std::string);
evmc::address computeCreateAddress(evmc::address, uint64_t nonce);
bool readBinaryFile(path, std::vector<uint8_t>&);
bool saveState(evmc::MockedHost const&, path);
bool loadState(evmc::MockedHost&, path);

// zen::utils (logging)
std::shared_ptr<ILogger> createConsoleLogger(name, LoggerLevel);
void zen::setGlobalLogger(ILogger);

// zen::utils (others)
void printTypedValueArray(std::vector<TypedValue> const&);
```

### Host Module Descriptors (Optional)

- `ZEN_ENABLE_BUILTIN_WASI`: `wasi_snapshot_preview1`
- `ZEN_ENABLE_BUILTIN_ENV`: `env`
- `ZEN_ENABLE_EVMABI_TEST`: `env` (reuses evmabimock context)

## Invariants and Permissions

- **Single main flow**: `main()` is single-threaded, sequential; no concurrent CLI subcommands
- **Config validation**: Depends on `RuntimeConfig::validate()` before creating `Runtime`; when `--enable-gdb-tracing-hook`, multipass multithreading is forcibly disabled
- **EVM mode restriction**: EVM runtime does not support `singlepass`; `Config.Mode != RunMode::SinglepassMode`
- **Isolation and instance lifecycle**: `createManagedIsolation` → `createInstance` / `createEVMInstance` → invoke → `deleteInstance` / `deleteEVMInstance` → `deleteManagedIsolation`
- **Benchmark mode**: Under `--benchmark` and `NDEBUG`, use `_exit()` or `::exit()` for early termination to avoid releasing resources and shorten measurement time

## Error Codes

| Source | Meaning |
|--------|---------|
| `EXIT_FAILURE` | Parse failure, runtime creation failure, module/instance load failure, Host module load failure, invocation failure, state save failure, etc. |
| `EXIT_SUCCESS` | Default success code in WASM mode when WASI is not enabled |
| `Inst->getExitCode()` | In WASM mode with WASI, exit code set by WASI `proc_exit` |
| `evmc_status_code` | In EVM mode, `ExeResult.status_code` used directly as process exit code (e.g. `EVMC_SUCCESS`, `EVMC_REVERT`, etc.) |

Parsing or initialization failures return `EXIT_FAILURE` uniformly; `evmc_status_code` is not output.

## Compatibility Strategy

- **Compile macros**: Behavior controlled by `ZEN_ENABLE_EVM`, `ZEN_ENABLE_BUILTIN_WASI`, `ZEN_ENABLE_BUILTIN_ENV`, `ZEN_ENABLE_EVMABI_TEST`, `ZEN_ENABLE_MULTIPASS_JIT`, `ZEN_ENABLE_PROFILER`, etc.
- **EVM options**: Only under `ZEN_ENABLE_EVM`: `--format evm`, `--calldata`, `--evm-revision`, `--deploy`, `--contract-address`, `--sender`, `--save-state`, `--load-state`, etc.
- **singlepass option**: Under `ZEN_ENABLE_EVM` build, `--mode` does not offer `singlepass`
- **Multipass options**: Only under `ZEN_ENABLE_MULTIPASS_JIT`: `--disable-multipass-greedyra`, `--disable-multipass-multithread`, `--num-multipass-threads`, `--enable-multipass-lazy`, `--enable-evm-gas`, `--entry-hint`
- **EVM version**: Supports `evmc_revision` from `frontier` to `osaka`; default `EVMC_CANCUN`

## Cross-References

- [runtime module](../runtime/spec.md): `Runtime`, `RuntimeConfig`, `Module`, `Instance`, `Isolation`, `HostModule`
- [common module](../common/spec.md): `InputFormat`, `RunMode`, `TypedValue`, `Error`, `MayBe`
- [utils module](../utils/spec.md): Logging, address parsing, hex conversion, state persistence
- [evm module](../evm/spec.md): EVM execution, `evmc_revision`, `DEFAULT_REVISION`
- [host module](../host/spec.md): WASI, env, evmabimock host modules
