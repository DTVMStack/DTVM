# platform Module Specification

> Directory: `src/platform/`

## Boundaries and Responsibilities

The platform module is DTVM's **OS/hardware abstraction layer**, providing unified runtime base capabilities between standard POSIX and Intel SGX enclave. Responsibilities include:

1. **Memory mapping abstraction**: Wrapper around `mmap`, `munmap`, `mprotect`; supports POSIX syscalls and SGX reserved memory interface
2. **File mapping**: Map files into process address space via `mapFile`/`unmapFile` (POSIX only; SGX not supported)
3. **Concurrency abstraction**: Type aliases for mutex, shared mutex, and RAII guards; use `std` on POSIX, placeholder implementations on SGX
4. **Time and I/O abstraction**: Clocks, file handles, output macros; upper code independent of execution environment
5. **SGX dependency injection**: Via `ocall_abort`, `ocall_print_string`, etc., delegate enclave fatal errors and logs to host process

The module does **not** include:
- Business logic or VM execution engine
- General data structures (containers and utilities in `common`)
- Logging implementation details (only I/O macros and file type aliases)

## Core Concepts

| Concept | Description |
|---------|-------------|
| **Platform switch** | Switch between POSIX and SGX via `ZEN_ENABLE_SGX` compile macro |
| **Memory mapping** | Associate virtual address range with physical resource; supports read/write/execute permission |
| **File mapping** | Map disk file to readable/writable memory via `MAP_PRIVATE` |
| **OCALL** | SGX mechanism to call host (untrusted) from enclave |
| **Type aliases** | `Mutex`, `SharedMutex`, `LockGuard`, etc. in `platform.h`; point to different implementations per platform |

## External Contracts

### 1. Namespace `zen::platform` (`map.h`)

| API | Signature | Behavior |
|-----|-----------|----------|
| `mmap` | `void *mmap(void *Addr, size_t Len, int Prot, int Flags, int Fd, size_t Offset)` | Map memory. `Len == 0` returns `nullptr`. POSIX failure: `ZEN_LOG_FATAL` then `abort`; SGX failure: `ocall_abort` |
| `munmap` | `void munmap(void *Addr, size_t Len)` | Unmap. Fatal on failure |
| `mprotect` | `void mprotect(void *Addr, size_t Len, int Prot)` | Change mapping permissions. Fatal on failure |
| `mapFile` | `bool mapFile(FileMapInfo *Info, const char *Filename)` | Open and map file. Returns `true` on success; `false` on failure or empty file. Always `false` on SGX with "unsupport mapFile in SGX" |
| `unmapFile` | `void unmapFile(const FileMapInfo *Info)` | Unmap file. Requires `Info && Info->Addr && Info->Length`. No-op on SGX |

### 2. Type Aliases (`platform.h`, namespace `zen::common`)

| Alias | Non-SGX | SGX |
|-------|---------|-----|
| `SharedMutex` | `std::shared_timed_mutex` | `SgxSharedMutex` |
| `Mutex` | `std::mutex` | `SgxMutex` |
| `LockGuard<T>` | `std::lock_guard<T>` | `SgxLockGuard<T>` |
| `SharedLock<T>` | `std::shared_lock<T>` | `SgxSharedLock<T>` |
| `UniqueLock<T>` | `std::unique_lock<T>` | `SgxUniqueLock<T>` |
| `STDFile` | `std::FILE` | `SGXFILE` |
| `SteadyClock` | `std::chrono::steady_clock` | `chrono::SystemClock` (note: platform macro uses `sgx::chrono::SystemClock`) |
| `SystemClock` | `std::chrono::system_clock` | `chrono::SystemClock` |

### 3. Macros (`platform.h`)

| Macro | Non-SGX | SGX |
|-------|---------|-----|
| `os_sdtout` | `::stdout` | `sgx_stdout` |
| `os_stderr` | `::stderr` | `sgx_stderr` |
| `os_write(fd, buf, count)` | `::write(...)` | `sgx_write(...)` |

### 4. SGX C Interface (`sgx/` headers, C linkage)

| Function | Description |
|----------|-------------|
| `ocall_abort()` | Host termination function; called on enclave failure |
| `ocall_print_string(const char *str)` | Host string output for logs, etc. |
| `int printf(const char *fmt, ...)` | Redirected to `ocall_print_string` |
| `int fprintf(SGXFILE *stream, const char *format, ...)` | Same |
| `ssize_t sgx_write(int fd, const void *buf, size_t n)` | Write interface; current stub returns `n` |
| `char *strdup(const char *str)` | String copy; implemented in `zen_sgx_string` |

## Invariants and Permissions

1. **`mmap` / `munmap` / `mprotect`**: On failure do not return; caller need not check (non-null return means success)
2. **`mapFile`**: `Info` must be non-null before call; on success `Info->Addr` and `Info->Length` valid; caller responsible for subsequent `unmapFile`
3. **`unmapFile`**: Requires `Info && Info->Addr && Info->Length` before call
4. **SGX `mmap`**: Size after page alignment must be < `UINT32_MAX`; uses `sgx_alloc_rsrv_mem`; failure returns `nullptr`

## Error Codes

- Module does not define its own error codes
- POSIX path: failure outputs `errno` via `ZEN_LOG_FATAL` and `abort`
- SGX path: failure outputs via `printf`/`ocall_print_string` and `ocall_abort`
- `mapFile` returning `false` indicates failure; not fatal

## Compatibility Strategy

1. **Compile-time switch**: `ZEN_ENABLE_SGX` selects implementation; external API unchanged
2. **ABI**: POSIX uses system `mmap`/`munmap`/`mprotect`; SGX uses `sgx_alloc_rsrv_mem`/`sgx_free_rsrv_mem`/`sgx_tprotect_rsrv_mem`
3. **File mapping**: SGX `mapFile` always fails; `unmapFile` is no-op; callers must not rely on file mapping on SGX
4. **Lock implementation**: SGX `SgxMutex` etc. are placeholders with no real sync semantics; for single-thread or host-guaranteed sync

## Cross-References

| Dependency | Description |
|------------|-------------|
| `common/defines.h` | `ZEN_ASSERT`, `ZEN_LOG_FATAL`, etc.; `platform.h` included by it |
| `utils/logging.h` | Logging interface (POSIX `map` uses `ZEN_LOG_*`) |
| SGX SDK | `sgx_error.h`, `sgx_rsrv_mem_mngr.h`, `unistd.h` (SGX version) |

| Depended By | Description |
|-------------|-------------|
| `common` | `defines.h` depends on `platform.h` |
| `runtime` | `memory.h` uses `platform/memory.h`; `codeholder.cpp` uses `platform/map.h` |
| `compiler` | `evm_compiler.cpp`, `common_defs.h` use `platform` |
| `evm` | `evm_cache.h` uses `platform.h` |
| `singlepass` | `singlepass.cpp` uses `platform/map.h` |
| `utils` | `logging`, `perf`, `virtual_stack` use `platform` |
