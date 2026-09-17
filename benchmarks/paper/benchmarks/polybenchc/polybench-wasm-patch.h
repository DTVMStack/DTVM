#pragma once

#ifdef WASM_TARGET

// 1. ftrace performance tracing
extern "C" int ftrace_begin(const char* label, int len);
extern "C" void ftrace_end();

#define polybench_start_instruments                    \
    do {                                               \
        const char* filename = strrchr(__FILE__, '/'); \
        if (filename)                                  \
            filename++;                                \
        else                                           \
            filename = __FILE__;                       \
        ftrace_begin(filename, strlen(filename) - 2);  \
    } while (0)

#define polybench_stop_instruments ftrace_end();

// 2. replace exit with abort for WASM
#ifdef __wasm__
[[clang::import_name("abort")]]
#endif
extern "C" [[noreturn]] void
_abort(const char* msg, uint32_t msg_len);

static inline void polybench_wasm_exit(int status)
{
    (void)status;
    _abort("call exit", 9u);
}

#undef exit
#define exit(status) polybench_wasm_exit(status)

// 3. export apply as WASM entry (main stays for native builds)
int main(int argc, char** argv);

extern "C" [[clang::export_name("apply")]] void apply(void)
{
    main(0, NULL);
}

#endif /* WASM_TARGET */
