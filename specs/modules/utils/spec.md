# utils Module Specification

> Directory: `src/utils/`

## Boundaries and Responsibilities

The utils module is DTVM's **utility and shared facilities layer**, providing cross-domain support for runtime, compiler, evm, etc. Responsibilities include:

1. **Logging**: Singleton Logging, ILogger interface, multiple logger implementations (console/async file/Spdlog), log macros
2. **Backtrace and debugging**: Stack frame backtrace `createBacktraceUntil`, CPU trap trigger `throwCpuIllegalInstructionTrap`
3. **Thread-safe containers**: `ThreadSafeMap`, `getThreadLocalUniqueId`
4. **Statistics and timing**: `Statistics` phase timing, `report` summary output
5. **Perf integration**: `PerfMapWriter` (perf map file), `JitDumpWriter` (JIT code mapping for `perf inject`)
6. **Virtual stack**: `StackMemPool`, `VirtualStackInfo` for WASM and EVM cross-stack calls
7. **WASM utilities**: LEB encode/decode, fixed-length read, block skip, type/opcode strings, Section order
8. **EVM utilities**: Hex/address/bytes32/uint256 parse and serialize, create address calculation, MockedHost state save/load
9. **General utilities**: String split, hex conversion, type-safe `bitCast`, TypedValue print, binary file read, RAMDisk detection
10. **Unicode/Math**: UTF-8 validation, arithmetic overflow detection (add/sub/mul)
11. **Filesystem**: `std::filesystem` or `std::experimental::filesystem` platform alias
12. **RLP encoding**: RLP encoding constants and functions in `zen::evm::rlp` namespace

**Excluded from scope**:

- RLP encoding in `src/utils/rlp_encoding.h` but namespace `zen::evm::rlp`; EVM helper
- Spdlog API only under `ZEN_ENABLE_SPDLOG`

## Core Concepts

| Concept | Description |
|---------|-------------|
| **Logging singleton** | Global unique Logger holder; replaceable via `setLogger`; multi-thread safe |
| **ILogger** | Six-level log interface (trace/debug/info/warn/error/fatal); implemented by SpdLoggerImpl, SimpleLoggerImpl, etc. |
| **ThreadSafeMap** | Read-heavy map wrapper over `common::SharedMutex`; read and write ops locked |
| **Statistics** | Phase timers by `StatisticPhase`; use `startRecord`/`stopRecord`/`revertRecord` in pairs |
| **PerfMapWriter / JitDumpWriter** | JIT code address mapping for Linux perf; symbol resolution |
| **StackMemPool** | Pre-allocated virtual stack memory for `VirtualStackInfo`; recyclable |
| **VirtualStackInfo** | Holds RSP/RBP, WASM/EVM call context; switch stack via `runInVirtualStack` |
| **LEB encode/decode** | WebAssembly Little Endian Base 128 variable-length integer; signed/unsigned |

## External Contracts

### 1. Logging (`logging.h`)

| API | Signature | Behavior |
|-----|-----------|----------|
| `Logging::getInstance` | `static Logging&` | Return singleton reference |
| `Logging::getLogger` | `std::shared_ptr<ILogger>` | Current Logger; may be null |
| `Logging::setLogger` | `void setLogger(std::shared_ptr<ILogger> NewLogger)` | Thread-safe replace Logger |
| `createConsoleLogger` | `std::shared_ptr<ILogger> createConsoleLogger(const std::string& LoggerName, LoggerLevel Level)` | Console Logger for CLI |
| `createAsyncFileLogger` | `std::shared_ptr<ILogger> createAsyncFileLogger(const std::string& LoggerName, const std::string& Filename, LoggerLevel Level)` | Async file Logger |
| `createSpdLogger` | `std::shared_ptr<ILogger> createSpdLogger(std::shared_ptr<spdlog::logger> SpdLogger)` | Only when `ZEN_ENABLE_SPDLOG` |
| `fmtString` | `template<typename... ArgsTypes> std::string fmtString(const char* Format, ArgsTypes... Args)` | Safe sprintf; returns `std::string` |

**Macros**: `ZEN_LOG_TRACE`, `ZEN_LOG_DEBUG`, `ZEN_LOG_INFO`, `ZEN_LOG_WARN`, `ZEN_LOG_ERROR`, `ZEN_LOG_FATAL`; usage `ZEN_LOG_INFO("msg %d", n)`.

### 2. Backtrace (`backtrace.h`)

| API | Signature | Behavior |
|-----|-----------|----------|
| `createBacktraceUntil` | `std::vector<void*> createBacktraceUntil(void* FrameAddr, void* PC, void* StartFrameAddr, uint32_t IgnoredDepth, void* UntilFuncStart, void* UntilFuncEnd, void* JITCode, void* JITCodeEnd)` | Walk stack collecting return addresses until UntilFuncStart/End or outside JIT; max `MAX_TRACE_LENGTH` frames |
| `throwCpuIllegalInstructionTrap` | `void throwCpuIllegalInstructionTrap()` | Only under `ZEN_ENABLE_CPU_EXCEPTION`; x86-64 emits `ud2`, AArch64 `udf #0xdead` |

### 3. Thread-Safe Container (`safe_map.h`)

| API | Signature | Behavior |
|-----|-----------|----------|
| `getThreadLocalUniqueId` | `int64_t getThreadLocalUniqueId()` | Thread-local monotonically increasing ID |
| `ThreadSafeMap<K,V>` | Template class | Map wrapper over `common::SharedMutex` |
| `empty`, `size` | Read lock | Same semantics as `std::map` |
| `operator[]`, `put`, `get`, `insert`, `emplace`, `erase`, `clear`, `swap` | Write lock | Write ops |
| `at`, `find`, `end`, `containsKey`, `count`, `lowerBound`, `upperBound`, `each` | Read lock | Read ops |
| `each(Handler)` | `void each(std::function<void(Key, Value)> Handler)` | Iterate key-value pairs; holds read lock |

### 4. Statistics (`statistics.h`)

| API | Signature | Behavior |
|-----|-----------|----------|
| `Statistics(bool Enabled)` | Constructor | When `Enabled==false` no recording |
| `startRecord` | `StatisticTimer startRecord(StatisticPhase Phase)` | Start timer; return Timer handle |
| `stopRecord` | `void stopRecord(StatisticTimer Timer)` | Stop and write to Records |
| `revertRecord` | `void revertRecord(StatisticTimer Timer)` | Cancel; do not write |
| `clearAllTimers` | `void clearAllTimers()` | Clear active timers |
| `report` | `void report() const` | Summarize Records and output to log |

### 5. Perf Integration (`perf.h`)

| API | Signature | Behavior |
|-----|-----------|----------|
| `PerfMapWriter` | Constructor opens `/tmp/perf-<pid>.map` | For perf script symbol resolution |
| `PerfMapWriter::writeLine` | `void writeLine(uint64_t Addr, uint64_t Len, const std::string& FuncName)` | Write one map entry |
| `JitDumpWriter` | Ctor/dtor manage `jit-<pid>.dump` and mmap | Linux perf JIT format |
| `JitDumpWriter::writeFunc` | `void writeFunc(std::string FuncName, uint64_t FuncAddr, uint64_t CodeSize)` | Write JIT_CODE_LOAD record |

### 6. Virtual Stack (`virtual_stack.h`)

| API | Signature | Behavior |
|-----|-----------|----------|
| `StackMemPool(size_t ItemSize)` | Constructor | Pre-allocate stack blocks; `MAX_STACK_ITEM_NUM=100` |
| `allocate` | `void* allocate(bool AllowReadWrite, bool* IsReused=nullptr)` | Allocate stack block; `IsReused` indicates reuse |
| `deallocate` | `void deallocate(void* Ptr)` | Return block |
| `VirtualStackInfo` | Struct | RSP/RBP, WASM Instance/Args/Results or EVM extension pointers |
| `VirtualStackInfo::allocate` | `void allocate()` | Allocate from StackMemPool |
| `VirtualStackInfo::runInVirtualStack` | `void runInVirtualStack(InVirtualStackFuncPtr Func)` | Switch stack and run Func |
| `VirtualStackInfo::rollbackStack` | `void rollbackStack()` | Restore stack and longjmp |
| `checkDwasmStackEnough` | `uint8_t checkDwasmStackEnough()` | Check dwasm stack space |

**extern "C"**: `startWasmFuncStack`, `rollbackWasmVirtualStack` provided by implementation for assembly/low-level calls.

### 7. WASM Utilities (`wasm.h`)

| API | Signature | Behavior |
|-----|-----------|----------|
| `readLEBNumber` | `template<typename T> const uint8_t* readLEBNumber(const uint8_t* Ip, const uint8_t* End, T& Value)` | Parse LEB; throw `LEBIntTooLong`/`LEBIntTooLarge` on out-of-bounds or too long |
| `readFixedNumber` | `template<typename T> const uint8_t* readFixedNumber(const uint8_t* Ip, const uint8_t* End, T& Value)` | Read `sizeof(T)` bytes, little-endian |
| `skipLEBNumber` | `template<typename T> const uint8_t* skipLEBNumber(const uint8_t* Ip, const uint8_t* End)` | Skip LEB without parsing |
| `skipBlockType` | `const uint8_t* skipBlockType(const uint8_t* Ip, const uint8_t* End)` | Skip block type |
| `skipCurrentBlock` | `const uint8_t* skipCurrentBlock(const uint8_t* Ip, const uint8_t* End)` | Skip current block (br/br_table/return/unreachable) |
| `getWASMTypeString` | `const char* getWASMTypeString(common::WASMType Type)` | Type name for dump |
| `getOpcodeString` | `const char* getOpcodeString(uint8_t Opcode)` | Opcode string |
| `getSectionOrder` | `common::SectionOrder getSectionOrder(common::SectionType SecType)` | Section order enum |

### 8. EVM Utilities (`evm.h`)

| API | Signature | Behavior |
|-----|-----------|----------|
| `trimString` | `void trimString(std::string& Str)` | In-place trim leading/trailing whitespace |
| `fromHex` | `std::optional<std::vector<uint8_t>> fromHex(std::string_view HexStr)` | Hex to bytes; invalid returns `nullopt` |
| `stripHexPrefix` | `std::string stripHexPrefix(const std::string& HexStr)` | Remove `0x` prefix |
| `hexToBytes` | `evmc::bytes hexToBytes(const std::string& HexStr)` | Hex to `evmc::bytes` |
| `parseAddress` | `evmc::address parseAddress(const std::string& HexAddr)` | 20-byte address parse |
| `parseBytes32` | `evmc::bytes32 parseBytes32(const std::string& HexStr)` | 32-byte parse |
| `parseUint256` | `evmc::uint256be parseUint256(const std::string& HexStr)` | 256-bit big-endian parse |
| `parseHexData` | `std::vector<uint8_t> parseHexData(const std::string& HexStr)` | General hex data parse |
| `addressToHex` | `std::string addressToHex(const evmc::address& Value)` | Address to hex |
| `bytes32ToHex` | `std::string bytes32ToHex(const evmc::bytes32& Value)` | bytes32 to hex |
| `bytesToHex` | `std::string bytesToHex(const std::vector<uint8_t>& Value)` | Byte vector to hex |
| `uint256beToBytes` | `std::vector<uint8_t> uint256beToBytes(const evmc::uint256be& Value)` | uint256be to bytes |
| `computeCreateAddress` | `evmc::address computeCreateAddress(const evmc::address& Sender, uint64_t SenderNonce)` | Create contract address |
| `saveState` | `bool saveState(const evmc::MockedHost& Host, const std::string& FilePath)` | MockedHost state persistence |
| `loadState` | `bool loadState(evmc::MockedHost& Host, const std::string& FilePath)` | MockedHost state load |

### 9. General Utilities (`others.h`)

| API | Signature | Behavior |
|-----|-----------|----------|
| `bitCast` | `template<typename DestType, typename SrcType> DestType bitCast(SrcType From)` | Type-safe bitwise cast |
| `split` | `std::vector<std::string> split(const std::string& Str, char Delim)` | Split by delimiter |
| `getOpcodeHexString` | `std::string getOpcodeHexString(uint8_t Opcode)` | Opcode hex string `"0x??"` |
| `printTypedValueArray` | `void printTypedValueArray(const std::vector<common::TypedValue>& Results)` | Print TypedValue array to stdout |
| `checkSupportRamDisk` | `bool checkSupportRamDisk()` | Darwin check `/Volumes/RAMDisk`; POSIX always true |
| `readBinaryFile` | `bool readBinaryFile(const std::string& Path, std::vector<uint8_t>& Data)` | Non-SGX only; read whole file as binary |
| `toHex` | `std::string toHex(const uint8_t* Bytes, size_t BytesCount)` | Bytes to uppercase hex string |

### 10. Unicode (`unicode.h`)

| API | Signature | Behavior |
|-----|-----------|----------|
| `validateUTF8String` | `bool validateUTF8String(const uint8_t* String, size_t Length)` | Validate UTF-8 encoding |

### 11. Math (`math.h`)

| API | Signature | Behavior |
|-----|-----------|----------|
| `addOverflow(T X, T Y, T& Result)` | Arithmetic/pointer overloads | Arithmetic: `__builtin_add_overflow`; pointer: `Ptr+Size`; returns overflow |
| `subOverflow` | `template<typename T> bool subOverflow(T X, T Y, T& Result)` | Unsigned only; `__builtin_sub_overflow` |
| `mulOverflow` | `template<typename T> bool mulOverflow(T X, T Y, T& Result)` | Unsigned only; `__builtin_mul_overflow` |

### 12. Filesystem (`filesystem.h`)

`namespace filesystem` is global alias; picks `std::filesystem` or `std::experimental::filesystem` by compiler support. Used as `using namespace filesystem` or `filesystem::path`, etc.

### 13. RLP Encoding (`rlp_encoding.h`, namespace `zen::evm::rlp`)

| API | Signature | Behavior |
|-----|-----------|----------|
| `RLP_OFFSET_SHORT_STRING` | `extern const uint8_t` | Short string offset 0x80 |
| `RLP_OFFSET_SHORT_LIST` | `extern const uint8_t` | Short list offset 0xc0 |
| `encodeLength` | `std::vector<uint8_t> encodeLength(size_t Length, uint8_t Offset)` | Encode RLP length |
| `encodeString` | `std::vector<uint8_t> encodeString(const std::vector<uint8_t>& Input)` | Encode RLP string |
| `encodeList` | `std::vector<uint8_t> encodeList(const std::vector<std::vector<uint8_t>>& Items)` | Encode RLP list |
| `encodeListFromEncodedItems` | `std::vector<uint8_t> encodeListFromEncodedItems(const std::vector<std::vector<uint8_t>>& Items)` | Build list from pre-encoded items |

## Invariants and Permissions

- **Logging**: `setLogger` holds `Mutex`; `getLogger` lock-free read of `shared_ptr`; concurrent safe
- **ThreadSafeMap**: Read ops hold `SharedLock`, write ops `UniqueLock`; iterator use outside lock requires caller safety
- **Statistics**: `startRecord` and `stopRecord`/`revertRecord` must pair; `Timers` must be empty on destruct
- **VirtualStackInfo**: `runInVirtualStack` switches stack; `Func` must not throw uncaught; `rollbackStack` returns via `longjmp`
- **StackMemPool**: `allocate` may block when no block available (non-SGX `AvailableCountCV`); `deallocate` `Ptr` must be from this pool
- **PerfMapWriter/JitDumpWriter**: Depends on `/tmp` and `getpid()`; POSIX only

## Error Codes

utils **uses** `common::ErrorCode`; does not define new codes:

| Error Code | Throw Location |
|------------|----------------|
| `LEBIntTooLong` | `wasm.h::readLEBNumber` (byte count over limit) |
| `LEBIntTooLarge` | `wasm.h::readLEBNumber` (value over limit) |
| `InvalidRawData` | `evm.cpp` (`fromHex`, `parseAddress`, `parseBytes32`, `parseUint256` parse failure) |

## Compatibility Strategy

- **Logger interface**: `ILogger` pure virtual stable; new implementations do not break callers
- **ThreadSafeMap**: Template interface matches `std::map`; Key/Value substitution does not break ABI
- **VirtualStackInfo**: `SavedPtr1/2/3` for EVM extension; when `ZEN_ENABLE_EVM` off, only WASM construction path
- **filesystem**: Switches `std` / `std::experimental` with compiler; no API change
- **EVM utilities**: Depends on evmc types; verify on evmc major upgrade

## Cross-References

- **Dependencies**: `common` (defines, type, errors, enums), `platform` (Mutex, SharedMutex, LockGuard, etc.), `evmc`
- **Depended by**: `platform` (logging in map impl), `runtime` (Instance, VirtualStackInfo), `compiler` (wasm utils), `evm` (evm utils, RLP), `action` (logging, others), `singlepass` (perf, backtrace)
- **Optional**: `spdlog` (`ZEN_ENABLE_SPDLOG`)
