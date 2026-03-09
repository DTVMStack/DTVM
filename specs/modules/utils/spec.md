# utils 模块规范

> 目录: `src/utils/`

## 边界与职责

utils 模块是 DTVM 的**工具函数与通用设施层**，为 runtime、compiler、evm 等上层模块提供跨领域的支撑能力。模块职责包括：

1. **日志系统**：单例 Logging、ILogger 接口、多种 Logger 实现（控制台/异步文件/Spdlog）、日志宏
2. **回溯与调试**：栈帧回溯 `createBacktraceUntil`、CPU trap 触发 `throwCpuIllegalInstructionTrap`
3. **线程安全容器**：`ThreadSafeMap`、`getThreadLocalUniqueId`
4. **统计与计时**：`Statistics` 阶段计时、`report` 汇总输出
5. **Perf 集成**：`PerfMapWriter`（perf map 文件）、`JitDumpWriter`（JIT 代码映射，供 `perf inject` 使用）
6. **虚拟栈**：`StackMemPool`、`VirtualStackInfo`，支持 WASM 与 EVM 跨栈调用
7. **WASM 工具函数**：LEB 编解码、固定长度读取、block 跳过、类型/操作码字符串、Section 顺序
8. **EVM 工具函数**：十六进制/地址/bytes32/uint256 解析与序列化、create 地址计算、MockedHost 状态保存/加载
9. **通用工具**：字符串分割、十六进制转换、类型安全 `bitCast`、TypedValue 打印、二进制文件读取、RAMDisk 检测
10. **Unicode/Math**：UTF-8 校验、算术溢出检测（add/sub/mul）
11. **文件系统**：`std::filesystem` 或 `std::experimental::filesystem` 的平台别名
12. **RLP 编码**：`zen::evm::rlp` 命名空间下的 RLP 编码常量与函数

**排除在边界外**：

- RLP 编码位于 `src/utils/rlp_encoding.h` 但命名空间为 `zen::evm::rlp`，属 EVM 辅助工具
- Spdlog 相关 API 仅在 `ZEN_ENABLE_SPDLOG` 下可用

## 核心概念

| 概念 | 描述 |
|------|------|
| **Logging 单例** | 全局唯一 Logger 持有者，通过 `setLogger` 可替换实现，支持多线程 |
| **ILogger** | 六级日志接口（trace/debug/info/warn/error/fatal），由 SpdLoggerImpl、SimpleLoggerImpl 等实现 |
| **ThreadSafeMap** | 基于 `common::SharedMutex` 的读多写少 map 包装，读写操作均加锁 |
| **Statistics** | 按 `StatisticPhase` 划分的阶段计时器，`startRecord`/`stopRecord`/`revertRecord` 成对使用 |
| **PerfMapWriter / JitDumpWriter** | 为 Linux perf 提供 JIT 代码地址映射，便于符号解析 |
| **StackMemPool** | 预分配大块虚拟栈内存，供 `VirtualStackInfo` 使用，支持回收复用 |
| **VirtualStackInfo** | 保存 RSP/RBP、WASM/EVM 调用上下文，通过 `runInVirtualStack` 切换到虚拟栈执行 |
| **LEB 编解码** | WebAssembly 使用的 Little Endian Base 128 变长整数，支持有符号/无符号 |

## 外部契约

### 1. 日志（`logging.h`）

| API | 签名 | 行为 |
|-----|------|------|
| `Logging::getInstance` | `static Logging&` | 返回单例引用 |
| `Logging::getLogger` | `std::shared_ptr<ILogger>` | 当前 Logger，可能为空 |
| `Logging::setLogger` | `void setLogger(std::shared_ptr<ILogger> NewLogger)` | 线程安全替换 Logger |
| `createConsoleLogger` | `std::shared_ptr<ILogger> createConsoleLogger(const std::string& LoggerName, LoggerLevel Level)` | 命令行工具用控制台 Logger |
| `createAsyncFileLogger` | `std::shared_ptr<ILogger> createAsyncFileLogger(const std::string& LoggerName, const std::string& Filename, LoggerLevel Level)` | 异步文件 Logger |
| `createSpdLogger` | `std::shared_ptr<ILogger> createSpdLogger(std::shared_ptr<spdlog::logger> SpdLogger)` | 仅 `ZEN_ENABLE_SPDLOG` 存在 |
| `fmtString` | `template<typename... ArgsTypes> std::string fmtString(const char* Format, ArgsTypes... Args)` | 安全 sprintf 格式化，返回 `std::string` |

**宏**：`ZEN_LOG_TRACE`、`ZEN_LOG_DEBUG`、`ZEN_LOG_INFO`、`ZEN_LOG_WARN`、`ZEN_LOG_ERROR`、`ZEN_LOG_FATAL`，用法 `ZEN_LOG_INFO("msg %d", n)`。

### 2. 回溯（`backtrace.h`）

| API | 签名 | 行为 |
|-----|------|------|
| `createBacktraceUntil` | `std::vector<void*> createBacktraceUntil(void* FrameAddr, void* PC, void* StartFrameAddr, uint32_t IgnoredDepth, void* UntilFuncStart, void* UntilFuncEnd, void* JITCode, void* JITCodeEnd)` | 从栈帧遍历收集返回地址，直到 `UntilFuncStart/End` 或超出 JIT 范围，最多 `MAX_TRACE_LENGTH` 帧 |
| `throwCpuIllegalInstructionTrap` | `void throwCpuIllegalInstructionTrap()` | 仅在 `ZEN_ENABLE_CPU_EXCEPTION` 下有效；x86-64 生成 `ud2`，AArch64 生成 `udf #0xdead` |

### 3. 线程安全容器（`safe_map.h`）

| API | 签名 | 行为 |
|-----|------|------|
| `getThreadLocalUniqueId` | `int64_t getThreadLocalUniqueId()` | 返回线程局部唯一递增 ID |
| `ThreadSafeMap<K,V>` | 模板类 | 基于 `common::SharedMutex` 的 map 包装 |
| `empty`, `size` | 读锁 | 与 `std::map` 语义一致 |
| `operator[]`, `put`, `get`, `insert`, `emplace`, `erase`, `clear`, `swap` | 写锁 | 写操作 |
| `at`, `find`, `end`, `containsKey`, `count`, `lowerBound`, `upperBound`, `each` | 读锁 | 读操作 |
| `each(Handler)` | `void each(std::function<void(Key, Value)> Handler)` | 遍历所有键值对，持读锁 |

### 4. 统计（`statistics.h`）

| API | 签名 | 行为 |
|-----|------|------|
| `Statistics(bool Enabled)` | 构造函数 | `Enabled==false` 时不记录 |
| `startRecord` | `StatisticTimer startRecord(StatisticPhase Phase)` | 开始计时，返回 Timer 句柄 |
| `stopRecord` | `void stopRecord(StatisticTimer Timer)` | 结束计时并写入 Records |
| `revertRecord` | `void revertRecord(StatisticTimer Timer)` | 取消计时，不写入 |
| `clearAllTimers` | `void clearAllTimers()` | 清空所有活跃计时器 |
| `report` | `void report() const` | 汇总 Records 并输出到日志 |

### 5. Perf 集成（`perf.h`）

| API | 签名 | 行为 |
|-----|------|------|
| `PerfMapWriter` | 构造函数打开 `/tmp/perf-<pid>.map` | 用于 perf script 符号解析 |
| `PerfMapWriter::writeLine` | `void writeLine(uint64_t Addr, uint64_t Len, const std::string& FuncName)` | 写入一行 map 条目 |
| `JitDumpWriter` | 构造/析构管理 `jit-<pid>.dump` 与 mmap 区 | Linux perf JIT 标准格式 |
| `JitDumpWriter::writeFunc` | `void writeFunc(std::string FuncName, uint64_t FuncAddr, uint64_t CodeSize)` | 写入 JIT_CODE_LOAD 记录 |

### 6. 虚拟栈（`virtual_stack.h`）

| API | 签名 | 行为 |
|-----|------|------|
| `StackMemPool(size_t ItemSize)` | 构造函数 | 预分配栈块，`MAX_STACK_ITEM_NUM=100` |
| `allocate` | `void* allocate(bool AllowReadWrite, bool* IsReused=nullptr)` | 分配一块栈，`IsReused` 指示是否复用 |
| `deallocate` | `void deallocate(void* Ptr)` | 归还栈块 |
| `VirtualStackInfo` | 结构体 | 保存 RSP/RBP、WASM Instance/Args/Results 或 EVM 扩展指针 |
| `VirtualStackInfo::allocate` | `void allocate()` | 从 StackMemPool 分配 |
| `VirtualStackInfo::runInVirtualStack` | `void runInVirtualStack(InVirtualStackFuncPtr Func)` | 切换栈并执行 Func |
| `VirtualStackInfo::rollbackStack` | `void rollbackStack()` | 恢复原栈并 longjmp |
| `checkDwasmStackEnough` | `uint8_t checkDwasmStackEnough()` | 检查 dwasm 是否有足够栈空间 |

**extern "C"**：`startWasmFuncStack`、`rollbackWasmVirtualStack` 由实现提供，供汇编或底层调用。

### 7. WASM 工具（`wasm.h`）

| API | 签名 | 行为 |
|-----|------|------|
| `readLEBNumber` | `template<typename T> const uint8_t* readLEBNumber(const uint8_t* Ip, const uint8_t* End, T& Value)` | 解析 LEB，越界或超长抛出 `LEBIntTooLong`/`LEBIntTooLarge` |
| `readFixedNumber` | `template<typename T> const uint8_t* readFixedNumber(const uint8_t* Ip, const uint8_t* End, T& Value)` | 读取 `sizeof(T)` 字节，小端 |
| `skipLEBNumber` | `template<typename T> const uint8_t* skipLEBNumber(const uint8_t* Ip, const uint8_t* End)` | 跳过 LEB 不解析 |
| `skipBlockType` | `const uint8_t* skipBlockType(const uint8_t* Ip, const uint8_t* End)` | 跳过 block type |
| `skipCurrentBlock` | `const uint8_t* skipCurrentBlock(const uint8_t* Ip, const uint8_t* End)` | 跳过当前 block（br/br_table/return/unreachable） |
| `getWASMTypeString` | `const char* getWASMTypeString(common::WASMType Type)` | 类型名，用于 dump |
| `getOpcodeString` | `const char* getOpcodeString(uint8_t Opcode)` | 操作码字符串 |
| `getSectionOrder` | `common::SectionOrder getSectionOrder(common::SectionType SecType)` | Section 顺序枚举 |

### 8. EVM 工具（`evm.h`）

| API | 签名 | 行为 |
|-----|------|------|
| `trimString` | `void trimString(std::string& Str)` | 原地去除首尾空白 |
| `fromHex` | `std::optional<std::vector<uint8_t>> fromHex(std::string_view HexStr)` | 十六进制转字节，非法返回 `nullopt` |
| `stripHexPrefix` | `std::string stripHexPrefix(const std::string& HexStr)` | 去除 `0x` 前缀 |
| `hexToBytes` | `evmc::bytes hexToBytes(const std::string& HexStr)` | 十六进制转 `evmc::bytes` |
| `parseAddress` | `evmc::address parseAddress(const std::string& HexAddr)` | 20 字节地址解析 |
| `parseBytes32` | `evmc::bytes32 parseBytes32(const std::string& HexStr)` | 32 字节解析 |
| `parseUint256` | `evmc::uint256be parseUint256(const std::string& HexStr)` | 256 位大端解析 |
| `parseHexData` | `std::vector<uint8_t> parseHexData(const std::string& HexStr)` | 通用十六进制数据解析 |
| `addressToHex` | `std::string addressToHex(const evmc::address& Value)` | 地址转十六进制 |
| `bytes32ToHex` | `std::string bytes32ToHex(const evmc::bytes32& Value)` | bytes32 转十六进制 |
| `bytesToHex` | `std::string bytesToHex(const std::vector<uint8_t>& Value)` | 字节向量转十六进制 |
| `uint256beToBytes` | `std::vector<uint8_t> uint256beToBytes(const evmc::uint256be& Value)` | uint256be 转字节 |
| `computeCreateAddress` | `evmc::address computeCreateAddress(const evmc::address& Sender, uint64_t SenderNonce)` | 创建合约地址 |
| `saveState` | `bool saveState(const evmc::MockedHost& Host, const std::string& FilePath)` | MockedHost 状态持久化 |
| `loadState` | `bool loadState(evmc::MockedHost& Host, const std::string& FilePath)` | MockedHost 状态加载 |

### 9. 通用工具（`others.h`）

| API | 签名 | 行为 |
|-----|------|------|
| `bitCast` | `template<typename DestType, typename SrcType> DestType bitCast(SrcType From)` | 类型安全按位转换 |
| `split` | `std::vector<std::string> split(const std::string& Str, char Delim)` | 按分隔符拆分 |
| `getOpcodeHexString` | `std::string getOpcodeHexString(uint8_t Opcode)` | 操作码十六进制字符串 `"0x??"` |
| `printTypedValueArray` | `void printTypedValueArray(const std::vector<common::TypedValue>& Results)` | 打印 TypedValue 数组到 stdout |
| `checkSupportRamDisk` | `bool checkSupportRamDisk()` | Darwin 检测 `/Volumes/RAMDisk`，POSIX 恒为 true |
| `readBinaryFile` | `bool readBinaryFile(const std::string& Path, std::vector<uint8_t>& Data)` | 仅非 SGX；读取整个文件为二进制 |
| `toHex` | `std::string toHex(const uint8_t* Bytes, size_t BytesCount)` | 字节转大写十六进制字符串 |

### 10. Unicode（`unicode.h`）

| API | 签名 | 行为 |
|-----|------|------|
| `validateUTF8String` | `bool validateUTF8String(const uint8_t* String, size_t Length)` | 校验 UTF-8 编码合法性 |

### 11. Math（`math.h`）

| API | 签名 | 行为 |
|-----|------|------|
| `addOverflow(T X, T Y, T& Result)` | 算术/指针版本 | 算术类型：`__builtin_add_overflow`；指针：`Ptr+Size`，返回是否溢出 |
| `subOverflow` | `template<typename T> bool subOverflow(T X, T Y, T& Result)` | 仅无符号，`__builtin_sub_overflow` |
| `mulOverflow` | `template<typename T> bool mulOverflow(T X, T Y, T& Result)` | 仅无符号，`__builtin_mul_overflow` |

### 12. 文件系统（`filesystem.h`）

`namespace filesystem` 为全局别名，根据编译器支持选择 `std::filesystem` 或 `std::experimental::filesystem`。供项目内 `using namespace filesystem` 或 `filesystem::path` 等用法。

### 13. RLP 编码（`rlp_encoding.h`，命名空间 `zen::evm::rlp`）

| API | 签名 | 行为 |
|-----|------|------|
| `RLP_OFFSET_SHORT_STRING` | `extern const uint8_t` | 短串偏移 0x80 |
| `RLP_OFFSET_SHORT_LIST` | `extern const uint8_t` | 短列表偏移 0xc0 |
| `encodeLength` | `std::vector<uint8_t> encodeLength(size_t Length, uint8_t Offset)` | 编码 RLP 长度 |
| `encodeString` | `std::vector<uint8_t> encodeString(const std::vector<uint8_t>& Input)` | 编码 RLP 字符串 |
| `encodeList` | `std::vector<uint8_t> encodeList(const std::vector<std::vector<uint8_t>>& Items)` | 编码 RLP 列表 |
| `encodeListFromEncodedItems` | `std::vector<uint8_t> encodeListFromEncodedItems(const std::vector<std::vector<uint8_t>>& Items)` | 从已编码项拼接列表 |

## 权限与不变量

- **Logging**：`setLogger` 持 `Mutex`，`getLogger` 无锁读 `shared_ptr`，可并发
- **ThreadSafeMap**：读操作持 `SharedLock`，写操作持 `UniqueLock`，迭代器在锁外使用需用户保证安全
- **Statistics**：`startRecord` 与 `stopRecord`/`revertRecord` 必须成对；析构时 `Timers` 必须为空
- **VirtualStackInfo**：`runInVirtualStack` 内部会切换栈，`Func` 中不得抛未捕获异常；`rollbackStack` 通过 `longjmp` 返回
- **StackMemPool**：`allocate` 在无可用块时可能阻塞（非 SGX 下 `AvailableCountCV`）；`deallocate` 的 `Ptr` 必须来自本池
- **PerfMapWriter/JitDumpWriter**：依赖 `/tmp` 与 `getpid()`，仅在 POSIX 环境有意义

## 错误码

utils 模块**使用** `common::ErrorCode`，不定义新错误码：

| 错误码 | 抛出位置 |
|--------|----------|
| `LEBIntTooLong` | `wasm.h::readLEBNumber`（字节数超限） |
| `LEBIntTooLarge` | `wasm.h::readLEBNumber`（值域超限） |
| `InvalidRawData` | `evm.cpp`（`fromHex`、`parseAddress`、`parseBytes32`、`parseUint256` 等解析失败） |

## 兼容性策略

- **Logger 接口**：`ILogger` 纯虚接口稳定，新增实现不破坏现有调用方
- **ThreadSafeMap**：模板接口与 `std::map` 行为一致，替换 Key/Value 类型不破坏 ABI
- **VirtualStackInfo**：`SavedPtr1/2/3` 用于 EVM 扩展，`ZEN_ENABLE_EVM` 关闭时仅保留 WASM 构造路径
- **filesystem**：随编译器切换 `std` / `std::experimental`，无 API 变更
- **EVM 工具**：依赖 evmc 类型，evmc 主版本升级需同步验证

## 交叉引用

- **依赖**：`common`（defines、type、errors、enums）、`platform`（Mutex、SharedMutex、LockGuard 等）、`evmc`
- **被依赖**：`platform`（logging 在 map 实现中使用）、`runtime`（Instance、VirtualStackInfo 使用）、`compiler`（wasm 工具）、`evm`（evm 工具、RLP）、`action`（logging、others）、`singlepass`（perf、backtrace）
- **可选依赖**：`spdlog`（`ZEN_ENABLE_SPDLOG`）
