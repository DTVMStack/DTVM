# platform 模块规范

> 目录: `src/platform/`

## 边界与职责

platform 模块是 DTVM 的 **OS/硬件抽象层**，负责在标准 POSIX 环境与 Intel SGX enclave 之间提供统一的运行时基础能力。模块职责包括：

1. **内存映射抽象**：对 `mmap`、`munmap`、`mprotect` 的封装，支持 POSIX 系统调用与 SGX 预留内存接口。
2. **文件映射**：通过 `mapFile`/`unmapFile` 将文件映射到进程地址空间（仅 POSIX；SGX 环境不支持）。
3. **并发原语抽象**：互斥锁、读写锁及其 RAII 守卫的类型别名，在 POSIX 下使用 `std`，在 SGX 下使用占位实现。
4. **时间与 I/O 抽象**：时钟、文件句柄、输出宏的统一接口，使上层代码不依赖具体运行环境。
5. **SGX 依赖注入**：通过 `ocall_abort`、`ocall_print_string` 等外部函数，将 enclave 内的致命错误与日志输出委托给宿主进程。

模块 **不** 包含：
- 业务逻辑或 VM 执行引擎；
- 通用数据结构（如 `common` 中的容器与工具）；
- 日志实现细节（仅提供 I/O 宏与文件类型别名）。

## 核心概念

| 概念 | 说明 |
|------|------|
| **平台切换** | 通过 `ZEN_ENABLE_SGX` 编译宏在 POSIX 与 SGX 两套实现间切换。 |
| **内存映射** | 将虚拟地址范围与物理资源关联，支持读/写/执行权限控制。 |
| **文件映射** | 将磁盘文件以 `MAP_PRIVATE` 方式映射为可读写的内存区域。 |
| **OCALL** | SGX 中从 enclave 调用宿主（untrusted）函数的机制。 |
| **类型别名** | `platform.h` 中定义的 `Mutex`、`SharedMutex`、`LockGuard` 等，随平台切换指向不同实现。 |

## 外部契约

### 1. 命名空间 `zen::platform`（`map.h`）

| API | 签名 | 行为 |
|-----|------|------|
| `mmap` | `void *mmap(void *Addr, size_t Len, int Prot, int Flags, int Fd, size_t Offset)` | 映射内存。`Len == 0` 返回 `nullptr`。POSIX 失败时调用 `ZEN_LOG_FATAL` 并 `abort`；SGX 失败时调用 `ocall_abort`。 |
| `munmap` | `void munmap(void *Addr, size_t Len)` | 解除映射。失败时同样致命退出。 |
| `mprotect` | `void mprotect(void *Addr, size_t Len, int Prot)` | 修改映射区域的权限。失败时致命退出。 |
| `mapFile` | `bool mapFile(FileMapInfo *Info, const char *Filename)` | 打开文件并映射。成功返回 `true`，失败或空文件返回 `false`。SGX 下始终返回 `false` 并打印 `"unsupport mapFile in SGX"`。 |
| `unmapFile` | `void unmapFile(const FileMapInfo *Info)` | 解除文件映射。调用前要求 `Info && Info->Addr && Info->Length`。SGX 下为空操作。 |

### 2. 类型别名（`platform.h`，命名空间 `zen::common`）

| 别名 | 非 SGX | SGX |
|------|--------|-----|
| `SharedMutex` | `std::shared_timed_mutex` | `SgxSharedMutex` |
| `Mutex` | `std::mutex` | `SgxMutex` |
| `LockGuard<T>` | `std::lock_guard<T>` | `SgxLockGuard<T>` |
| `SharedLock<T>` | `std::shared_lock<T>` | `SgxSharedLock<T>` |
| `UniqueLock<T>` | `std::unique_lock<T>` | `SgxUniqueLock<T>` |
| `STDFile` | `std::FILE` | `SGXFILE` |
| `SteadyClock` | `std::chrono::steady_clock` | `chrono::SystemClock`（注：平台宏下为 `sgx::chrono::SystemClock`） |
| `SystemClock` | `std::chrono::system_clock` | `chrono::SystemClock` |

### 3. 宏（`platform.h`）

| 宏 | 非 SGX | SGX |
|----|--------|-----|
| `os_sdtout` | `::stdout` | `sgx_stdout` |
| `os_stderr` | `::stderr` | `sgx_stderr` |
| `os_write(fd, buf, count)` | `::write(...)` | `sgx_write(...)` |

### 4. SGX C 接口（`sgx/` 头文件，C linkage）

| 函数 | 说明 |
|------|------|
| `ocall_abort()` | 宿主实现的终止函数，enclave 内失败时调用。 |
| `ocall_print_string(const char *str)` | 宿主实现的字符串输出，用于日志等。 |
| `int printf(const char *fmt, ...)` | 重定向到 `ocall_print_string`。 |
| `int fprintf(SGXFILE *stream, const char *format, ...)` | 同上。 |
| `ssize_t sgx_write(int fd, const void *buf, size_t n)` | 写入接口，当前 stub 实现返回 `n`。 |
| `char *strdup(const char *str)` | 字符串复制，在 `zen_sgx_string` 中实现。 |

## 权限与不变量

1. **`mmap` / `munmap` / `mprotect`**：失败不返回，调用方无需检查返回值（非空返回值即成功）。
2. **`mapFile`**：调用前 `Info` 非空；成功时 `Info->Addr` 与 `Info->Length` 有效，调用方负责后续调用 `unmapFile`。
3. **`unmapFile`**：调用前满足 `Info && Info->Addr && Info->Length`。
4. **SGX `mmap`**：请求大小经页对齐后不得 ≥ `UINT32_MAX`；使用 `sgx_alloc_rsrv_mem` 分配，失败返回 `nullptr`。

## 错误码

- 模块本身不定义独立错误码。
- POSIX 路径：失败时通过 `ZEN_LOG_FATAL` 输出 `errno` 并 `abort`。
- SGX 路径：失败时通过 `printf`/`ocall_print_string` 输出信息并调用 `ocall_abort`。
- `mapFile` 返回 `false` 表示失败，不致命退出。

## 兼容性策略

1. **编译期切换**：通过 `ZEN_ENABLE_SGX` 选择实现，对外 API 保持一致。
2. **ABI**：POSIX 使用系统 `mmap`/`munmap`/`mprotect`；SGX 使用 `sgx_alloc_rsrv_mem`/`sgx_free_rsrv_mem`/`sgx_tprotect_rsrv_mem`。
3. **文件映射**：SGX 下 `mapFile` 永远失败，`unmapFile` 为空操作，调用方需避免在 SGX 下依赖文件映射。
4. **锁实现**：SGX 下 `SgxMutex` 等为占位类型，无实际同步语义，适用于单线程或宿主保证的同步场景。

## 交叉引用

| 依赖 | 说明 |
|------|------|
| `common/defines.h` | `ZEN_ASSERT`、`ZEN_LOG_FATAL` 等宏；`platform.h` 被其包含。 |
| `utils/logging.h` | 日志接口（POSIX 路径的 `map` 实现使用 `ZEN_LOG_*`）。 |
| SGX SDK | `sgx_error.h`、`sgx_rsrv_mem_mngr.h`、`unistd.h`（SGX 版本）。 |

| 被依赖 | 说明 |
|--------|------|
| `common` | `defines.h` 依赖 `platform.h`。 |
| `runtime` | `memory.h` 使用 `platform/memory.h`；`codeholder.cpp` 使用 `platform/map.h`。 |
| `compiler` | `evm_compiler.cpp`、`common_defs.h` 使用 `platform`。 |
| `evm` | `evm_cache.h` 使用 `platform.h`。 |
| `singlepass` | `singlepass.cpp` 使用 `platform/map.h`。 |
| `utils` | `logging`、`perf`、`virtual_stack` 使用 `platform`。 |
