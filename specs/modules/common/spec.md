# common 模块规范

> 目录: `src/common/`

## 边界与职责

common 模块是 DTVM 的核心基础设施层，提供全项目共享的基础抽象、类型定义和通用能力。

**核心职责**:

- **共享类型与常量**: WASM/EVM 类型体系、操作码枚举、WebAssembly 预设限制常量
- **错误体系**: 统一的 `Error` 异常类、错误码枚举、错误查询与格式化 API
- **内存池**: 多种策略的内存分配器（系统池、代码池等），支持 STL 分配器适配
- **字符串池**: 常量字符串去重与引用计数（WASM symbol 管理）
- **操作码与运算符**: WASM 操作码定义、二元/一元/比较运算符枚举
- **Trap 处理**: 基于 CPU 信号（SIGILL/SIGSEGV 等）的 JIT trap 捕获与回滚，支持 WASM 与 EVM 两套实现

**排除在边界外**:

- `libcxx/` 下的 C++17 兼容层为平台抽象的一部分，不由 common 单独定义
- `common/wasm_defs/` 由 `.def` 宏展开生成枚举，内容归 common 所有，但定义分散在多个 `.def` 文件中

## 核心概念

| 概念 | 描述 |
|------|------|
| **WASMSymbol / EVMSymbol** | 字符串池中的符号句柄，`uint32_t`，0 表示空 |
| **Error 体系** | `ErrorPhase` → `ErrorSubphase` → `ErrorCode` 的分层错误模型 |
| **MemPool** | 模板化的内存池，按 `MemPoolKind` 选择策略（SYS_POOL、CODE_POOL 等） |
| **ConstStringPool** | 基于哈希表的常量字符串池，支持 `probeSymbol`（不增加引用）与 `newSymbol`（增加引用） |
| **TrapHandler** | 在 `ZEN_ENABLE_CPU_EXCEPTION` 下，通过信号处理器捕获 JIT 执行中的 trap，并使用 `longjmp` 回滚 |
| **CallThreadState / EVMCallThreadState** | 线程局部 trap 调用状态，记录 PC、栈帧、Gas 寄存器等，用于 JIT 栈回溯 |

## 外部契约

### 错误与可选值

```cpp
// 错误查询
Error getError(ErrorCode ErrCode);
Optional<Error> getErrorOrNone(ErrorCode ErrCode);  // 若 ErrCode 无定义则返回 Nullopt
Error getErrorWithPhase(ErrorCode ErrCode, ErrorPhase Phase, ErrorSubphase Subphase = None);
Error getErrorWithExtraMessage(ErrorCode ErrCode, const std::string& ExtraMessage);

// 可选值包装（仅指针类型）
template<typename T> class MayBe<T>;  // T 必须为指针，包装 Value 或 Error
```

### 字符串池

```cpp
class ConstStringPool {
  bool initPool();
  void destroyPool();
  WASMSymbol newSymbol(const char* Str, size_t Len);
  void freeSymbol(WASMSymbol Sym);
  int32_t getNumSymbols();
  const char* dumpSymbolString(WASMSymbol Sym);
  WASMSymbol probeSymbol(const char* Str, size_t Len) const;  // 不增加 refcount
};
```

### 内存池

```cpp
// SysMemPool - 基于 malloc/free
void* allocate(size_t Size, size_t Align = 0, const char* TypeName = nullptr);
void* allocateZeros(size_t Size, size_t Align = 0, const char* TypeName = nullptr);
void deallocate(void* Ptr);
void* reallocate(void* OldPtr, size_t OldSize, size_t NewSize);
T* newObject(Arguments&&... Args);
void deleteObject(T* Ptr);

// CodeMemPool - mmap 代码缓存，线程安全
void* allocate(size_t Size, size_t Align = DefaultAlign);
// getMemStart(), getMemEnd(), getMemPageEnd()
```

### Trap 初始化（`ZEN_ENABLE_CPU_EXCEPTION`）

```cpp
// WASM JIT
namespace common::traphandler {
  bool initPlatformTrapHandler();
}

// EVM JIT
namespace common::evm_traphandler {
  bool initEVMPlatformTrapHandler();
}
```

### 类型与运算符

```cpp
// 类型查询
WASMType getWASMValTypeFromOpcode(uint8_t Opcode);
WASMType getWASMBlockTypeFromOpcode(uint8_t Opcode);
WASMType getWASMRefTypeFromOpcode(uint8_t Opcode);
uint32_t getWASMTypeSize(WASMType Type);
uint32_t getWASMTypeCellNum(WASMType Type);
WASMTypeKind getWASMTypeKind(WASMType Type);

// 比较运算符取反（用于操作数交换后的比较）
template<CompareOperator opr>
constexpr CompareOperator getExchangedCompareOperator();
```

## 权限与不变量

| 不变量 | 描述 |
|--------|------|
| **ConstStringPool** | 保留符号（`Sym < WASM_SYMBOLS_END`）不可 `freeSymbol`；`probeSymbol` 不持有生命周期，调用方需保证字符串存活 |
| **MemPool** | `SysMemPool` 在 NDEBUG 下跟踪未释放分配，析构时断言全释放；`CODE_POOL` 不可拷贝 |
| **Error** | `ErrorCode` 底层类型固定为 `uint32_t`，供 JIT 使用 |
| **TrapHandler** | `initPlatformTrapHandler` / `initEVMPlatformTrapHandler` 应在单一编译单元、仅调用一次 |
| **ThreadPool** | 析构前需 `waitForTasks()` 或 `interrupt()`，否则行为未定义 |

## 错误码

错误码由 `common/errors.def` 宏展开生成，分类如下：

| 阶段 | 子阶段 | 代表错误码 |
|------|--------|-------------|
| BeforeLoad | None | InvalidFilePath, FileAccessFailed, InvalidRawData, InvalidModuleName |
| Load | None | MagicNotDetected, UnknownBinaryVersion, TooManyTypes, TooManyFunctions, ... |
| Instantiation | None | DataSegmentDoesNotFit, ElementsSegmentDoesNotFit |
| Compilation | Lexing/Parsing/ContextInit/... | UnsupportedToken, NoMatchedSyntax, RegAllocFailed, ... |
| BeforeExecution | None | CannotFindFunction, UnexpectedNumArgs, InvalidArgument, ... |
| Execution | None | IntegerOverflow, OutOfBoundsMemory, CallStackExhausted, GasLimitExceeded, ... |

**EVM 特有**（`ZEN_ENABLE_EVM`）: EVMStackOverflow, EVMStackUnderflow, EVMBadJumpDestination, EVMInvalidInstruction, EVMFrameNotFound, EVMStaticModeViolation 等。

**dWasm 特有**（`ZEN_ENABLE_DWASM`）: DWasmFuncBodyTooLarge, DWasmLocalsTooMany, DWasmOutOfGas 等。

## 兼容性策略

- **ErrorCode**：新增错误码应追加，不删除或修改既有枚举值，以保证 JIT 中 uint32_t 错误码语义稳定
- **WASM 操作码**：与 WebAssembly 规范对齐，`opcode.def` 变更需评估对编译器与解释器的影响
- **ConstStringPool 保留符号**：`const_strings.def` 中预定义符号的索引应保持稳定
- **MemPool API**：allocate/deallocate 签名保持稳定；`reallocate` 仅 `SysMemPool` 提供

## 交叉引用

| 依赖 | 说明 |
|------|------|
| `platform/platform.h` | 互斥锁、Optional、to_underlying、chrono 等平台抽象 |
| `platform/map.h` | mmap/munmap/mprotect，用于 CodeMemPool |

| 被依赖 | 说明 |
|--------|------|
| compiler | 使用 MemPool、enums、operators、type、errors |
| runtime | 使用 traphandler、evm_traphandler、errors、defines、type |
| action | 使用 const_string_pool、mem_pool、errors、defines |
| host | 使用 errors、defines、type |
| vm-interface | 使用 RunMode、InputFormat、RuntimeConfig、errors、defines |
| evmc | 使用 errors、defines（evmc 库类型，经 vm-interface 等） |
| tests | 使用 common 全部能力 |
