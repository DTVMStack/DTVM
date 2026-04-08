# Runtime Module Data Model

## Entity Relationship Diagram (Mermaid classDiagram)

```mermaid
classDiagram
    direction TB

    class Runtime {
        -MemPool MPool
        -ConstStringPool SymbolPool
        -HostModulePool
        -ModulePool
        -EVMModulePool
        -Isolations
        +newRuntime(Config)
        +newEVMRuntime(Config, EVMHost)
        +loadHostModule(BuiltinModuleDesc)
        +loadModule(Filename/ModName, Data)
        +loadEVMModule(Filename/ModName, Data, Rev)
        +createManagedIsolation()
        +createUnmanagedIsolation()
        +callWasmMain(Instance, Results)
        +callWasmFunction(Instance, FuncIdx/FuncName, Args, Results)
        +callEVMMain(EVMInstance, Msg, Result)
    }

    class RuntimeObject~T~ {
        #Runtime* RT
        +getRuntime()
        +allocate/deallocate/reallocate
        +newSymbol/probeSymbol/freeSymbol
    }

    class BaseModule~T~ {
        #ModuleType Type
        #WASMSymbol Name
        +getName()
        +setName()
    }

    class HostModule {
        -VNMIEnvInternal _vnmi_env
        -MainModDesc
        -HostModMap
        -HostFunctionList
        +newModule(RT, ModDesc)
        +getVNMIEnv()
        +getHostFuntionList()
        +addFunctions()
    }

    class Module {
        -CodeHolder
        -TypeTable
        -ImportFunctionTable
        -InternalFunctionTable
        -CodeTable
        -Layout InstanceLayout
        -JITCode
        +newModule(RT, CodeHolder, EntryHint)
        +getLayout()
        +getMemoryAllocator()
        +getJITCode()
    }

    class EVMModule {
        -CodeHolder
        -Byte* Code
        -size_t CodeSize
        -evmc::Host* Host
        -EVMBytecodeCache
        -evmc_revision Revision
        +newEVMModule(RT, CodeHolder, Rev)
        +getJITCode()
    }

    class Isolation {
        -WNIEnvInternal WniEnv
        -InstancePool
        -EVMInstancePool
        +newIsolation(RT)
        +createInstance(Module, GasLimit)
        +createEVMInstance(EVMModule, GasLimit)
        +deleteInstance()
        +deleteEVMInstance()
    }

    class Instance {
        -Isolation* Iso
        -const Module* Mod
        -FunctionInstance* Functions
        -MemoryInstance* Memories
        -TableInstance* Tables
        -GlobalInstance* Globals
        +getModule()
        +getFunctionInst()
        +getDefaultMemoryInst()
        +growLinearMemory()
        +setError/getError()
    }

    class EVMInstance {
        -const EVMModule* Mod
        -uint8_t* MemoryBase
        -uint64_t MemorySize
        -ExecutionCache
        -MessageStack
        +getModule()
        +getGas/setGas()
        +getMemory()
        +pushMessage/popMessage()
        +getExeResult/setExeResult()
    }

    class WasmMemoryAllocator {
        -Module* CurModule
        -WasmMemoryDataType DefaultMemoryType
        +allocInitWasmMemory()
        +enlargeWasmMemory()
        +freeWasmMemory()
        +mprotectReadWriteWasmMemoryData()
    }

    class CodeHolder {
        -HolderKind Kind
        -const void* Data
        -size_t Size
        +newFileCodeHolder()
        +newRawDataCodeHolder()
    }

    Runtime "1" --> "*" Isolation : manages
    Runtime "1" --> "*" HostModule : holds
    Runtime "1" --> "*" Module : holds
    Runtime "1" --> "*" EVMModule : holds

    Isolation "1" --> "*" Instance : holds
    Isolation "1" --> "*" EVMInstance : holds

    Instance "*" --> "1" Module : references
    EVMInstance "*" --> "1" EVMModule : references

    Module "1" --> "1" WasmMemoryAllocator : per-thread
    Module "1" --> "1" CodeHolder : holds

    EVMModule --> BaseModule
    Module --> BaseModule
    HostModule --> BaseModule
    BaseModule --> RuntimeObject
    Isolation --> RuntimeObject
    Instance --> RuntimeObject
    EVMInstance --> RuntimeObject
    CodeHolder --> RuntimeObject
```

## Core Entities (Key Fields and Methods)

### Runtime

| Field / Method | Description |
|----------------|-------------|
| `MPool` | System memory pool (SysMemPool) |
| `SymbolPool` | Constant string pool (ConstStringPool) |
| `HostModulePool` | `WASMSymbol -> HostModuleUniquePtr` |
| `ModulePool` | `WASMSymbol -> ModuleUniquePtr` |
| `EVMModulePool` | `EVMSymbol -> EVMModuleUniquePtr` (ZEN_ENABLE_EVM) |
| `Isolations` | `Isolation* -> IsolationUniquePtr` |
| `EVMHost` | evmc::Host* (ZEN_ENABLE_EVM) |
| `VMMaxMemPages` | Maximum linear memory pages for the VM |
| `Config` | RuntimeConfig |

### Module

| Field / Method | Description |
|----------------|-------------|
| `TypeTable` | TypeEntry* |
| `ImportFunctionTable` | ImportFunctionEntry* |
| `InternalFunctionTable` | FuncEntry* |
| `CodeTable` | CodeEntry* |
| `Layout` | InstanceLayout; computes Instance memory layout |
| `JITCode` / `JITCodeSize` | JIT compilation output (ZEN_ENABLE_JIT) |
| `ThreadLocalMemAllocatorMap` | Thread -> WasmMemoryAllocator* |

### Instance

| Field / Method | Description |
|----------------|-------------|
| `Mod` | Associated Module |
| `Iso` | Associated Isolation |
| `Functions` | FunctionInstance array |
| `Memories` | MemoryInstance array |
| `Tables` | TableInstance array |
| `Globals` | GlobalInstance array |
| `GlobalVarData` | Global variable storage |
| `Err` | common::Error |
| `Gas` | Gas limit / remaining |
| `JITFuncPtrs` / `FuncTypeIdxs` | JIT metadata (ZEN_ENABLE_JIT) |

### EVMInstance

| Field / Method | Description |
|----------------|-------------|
| `Mod` | Associated EVMModule |
| `Memory` | std::unique_ptr<uint8_t[]> |
| `MemoryBase` / `MemorySize` | Current memory base address and size |
| `EVMStack` | uint8_t[EVMStackCapacity] |
| `CurrentMessage` / `MessageStack` | evmc_message call stack |
| `ExeResult` | evmc::Result |
| `InstanceExecutionCache` | ExecutionCache (TxContext, BlockHashes, etc.) |
| `Gas` / `GasRefund` | Gas and refund |

### Isolation

| Field / Method | Description |
|----------------|-------------|
| `WniEnv` | WNIEnvInternal (WNI environment) |
| `InstancePool` | Instance* -> InstanceUniquePtr |
| `EVMInstancePool` | EVMInstance* -> EVMInstanceUniquePtr (ZEN_ENABLE_EVM) |

### WasmMemoryAllocator

| Field / Method | Description |
|----------------|-------------|
| `CurModule` | Associated Module |
| `DefaultMemoryType` | WasmMemoryDataType |
| `ActiveBuckets` | MmapBucketInstance map |
| `allocInitWasmMemory()` | Allocate initial linear memory |
| `enlargeWasmMemory()` | Grow memory |
| `freeWasmMemory()` | Free memory |

## Enumerations

### ModuleType

```cpp
enum class ModuleType { WASM, EVM, JIT, AOT, NATIVE };
```

### FunctionKind

```cpp
enum FunctionKind { ByteCode = 0, Jit, Aot, Native };
```

### WasmMemoryDataType

```cpp
enum WasmMemoryDataType : uint32_t {
  WM_MEMORY_DATA_TYPE_NO_DATA = 0,
  WM_MEMORY_DATA_TYPE_MALLOC = 1,
  WM_MEMORY_DATA_TYPE_SINGLE_MMAP = 2,
  WM_MEMORY_DATA_TYPE_BUCKET_MMAP = 3,
};
```

### CodeHolder::HolderKind

```cpp
enum class HolderKind { kFile, kRawData };
```

## DTO / Shared Types

### VNMIEnvInternal

```cpp
typedef struct VNMIEnvInternal_ {
  VNMIEnv _env;
  Runtime *_runtime;
} VNMIEnvInternal;
```

### WNIEnvInternal

```cpp
typedef struct WNIEnvInternal_ {
  WNIEnv _env;
  Runtime *_runtime;
} WNIEnvInternal;
```

### BuiltinModuleDesc (from vnmi.h)

| Field | Description |
|-------|-------------|
| `_name` | Module name |
| `_load_func` | LOAD_FUNC_PTR |
| `_unload_func` | UNLOAD_FUNC_PTR |
| `_init_ctx_func` | INITCTX_FUNC_PTR |
| `_destroy_ctx_func` | DESTROYCTX_FUNC_PTR |
| `Functions` | NativeFuncDesc* |
| `NumFunctions` | Function count |

### NativeFuncDesc (from vnmi.h)

| Field | Description |
|-------|-------------|
| `_name` | VMSymbol function name |
| `_ptr` | Function pointer |
| `_func_type` | WASMType* |
| `_param_count` | Parameter count |
| `_ret_count` | Return value count |
| `_isReserved` | Whether reserved |

### WasmMemoryData

```cpp
struct WasmMemoryData {
  WasmMemoryDataType Type;
  uint8_t *MemoryData;
  size_t MemorySize;
  bool NeedMprotect;
};
```

### FunctionInstance

| Field | Description |
|-------|-------------|
| `NumParams` / `NumLocals` | Parameter / local variable counts |
| `MaxStackSize` / `MaxBlockDepth` | Stack and block depth |
| `Kind` | FunctionKind |
| `CodePtr` | Bytecode pointer |
| `JITCodePtr` | JIT code pointer (ZEN_ENABLE_JIT) |
| `ReturnTypes` / `ParamTypes` | Type information |

### MemoryInstance

| Field | Description |
|-------|-------------|
| `CurPages` / `MaxPages` | Current / maximum page count |
| `MemSize` | Size in bytes |
| `MemBase` / `MemEnd` | Base and end address |
| `Kind` | WasmMemoryDataType |

### TableInstance

| Field | Description |
|-------|-------------|
| `CurSize` / `MaxSize` | Current / maximum element count |
| `Elements` | uint32_t* table entries |

### GlobalInstance

| Field | Description |
|-------|-------------|
| `Type` | WASMType |
| `Mutable` | Whether mutable |
| `Offset` | Offset in GlobalVarData |

### RuntimeConfig

| Field | Description |
|-------|-------------|
| `Format` | common::InputFormat |
| `Mode` | common::RunMode |
| `DisableWasmMemoryMap` | Whether to disable mmap |
| `EnableStatistics` | Whether to enable statistics |
| `DisableWASI` | Whether to disable WASI (ZEN_ENABLE_BUILTIN_WASI) |
| `EnableMultipassLazy` | Multipass lazy compilation (ZEN_ENABLE_MULTIPASS_JIT) |

### RuntimeObjectDestroyer and UniquePtr Types

```cpp
template <typename T> using RuntimeObjectUniquePtr = std::unique_ptr<T, RuntimeObjectDestroyer>;
using CodeHolderUniquePtr = RuntimeObjectUniquePtr<CodeHolder>;
using HostModuleUniquePtr = RuntimeObjectUniquePtr<HostModule>;
using ModuleUniquePtr = RuntimeObjectUniquePtr<Module>;
using InstanceUniquePtr = RuntimeObjectUniquePtr<Instance>;
using IsolationUniquePtr = RuntimeObjectUniquePtr<Isolation>;
using EVMModuleUniquePtr = RuntimeObjectUniquePtr<EVMModule>;  // ZEN_ENABLE_EVM
using EVMInstanceUniquePtr = RuntimeObjectUniquePtr<EVMInstance>;  // ZEN_ENABLE_EVM
```
