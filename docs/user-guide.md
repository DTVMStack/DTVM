<a name="RKIDy"></a>
## Compilation and Build
The current features of `ZetaEngine` are controlled using macros. The main macro switches in the code are as follows:

| Macro | Description | Default Value |
| --- | --- | --- |
| ZEN_ENABLE_ASAN | Enable ASAN to check for memory leaks | OFF |
| ZEN_ENABLE_DUMP_CALL_STACK | Enable call stack dumping on exceptions | OFF |
| ZEN_ENABLE_SINGLEPASS_JIT | Enable single-pass JIT functionality | OFF |
| ZEN_ENABLE_MULTIPASS_JIT | Enable multi-pass JIT functionality | OFF |
| ZEN_ENABLE_JIT_LOGGING | Enable logging in JIT | OFF |
| ZEN_ENABLE_BUILTIN_WASI | Enable built-in WASI | ON |
| ZEN_ENABLE_BUILTIN_LIBC | Enable built-in libc (partial) | ON |
| ZEN_ENABLE_CHECKED_ARITHMETIC | Enable overflow checks | OFF |
| ZEN_ENABLE_VIRTUAL_STACK | Enable virtual stack | OFF |
| ZEN_ENABLE_SPEC_TEST | Enable spec tests | OFF |
| ZEN_ENABLE_DWASM | Enable DWASM functionality | OFF |
| ZEN_ENABLE_ASSEMBLYSCRIPT_TEST | Enable AssemblyScript tests | OFF |
| ZEN_ENABLE_PROFILER | Enable profiler functionality | OFF |
| ZEN_ENABLE_LINUX_PERF | Enable Linux perf functionality | OFF |
| ZEN_ENABLE_DEBUG_GREEDY_RA | Enable debugging for greedy RA | OFF |
| ZEN_ENABLE_CPU_EXCEPTION | Use CPU traps to implement WASM traps | ON |

Explanation:

- `CMAKE_BUILD_TYPE` can be set to `release` or `debug`. Other configuration features can be enabled by adding the corresponding macros as needed.
- After compilation, two binary files, `dtvm` and `dtvmTest`, will be generated in the `build` directory.

<a name="WxBjy"></a>
## Command Line Instructions
<a name="cwReD"></a>
### Commands for `dtvm`
| Command | Description | Default Value |
| --- | --- | --- |
| -dir | (directory) <br />type: string | "" |
| -env | (environment variables)<br />type: string | "" |
| -f | (function name) <br />type: string | "" |
| -args | (function parameters) <br />type: string | "" |
| -log | (log level: <br />0/trace <br />1/debug <br />2/info<br />3/warn<br />4/error<br />5/fatal) <br />type: string | "2"/"info" |
| -mode | (execution mode: <br />0/interpreter<br />1/singlepass <br />2/multipass) <br />type: string | "0"/"interpreter" |
| -repl | (REPL mode) type: bool | false |

<a name="AcMiv"></a>
### Commands for `dtvmTest`
| Command | Description | Default Value |
| --- | --- | --- |
| -compileTimes | (Set the number of compilation runs) <br />type: uint32 | 1 |
| -dir | (directory) <br />type: string | "" |
| -env | (environment variables)<br />type: string | "" |
| -f | (function name) <br />type: string | "" |
| -args | (function parameters) <br />type: string | "" |
| -log | (log level: <br />0/trace <br />1/debug <br />2/info<br />3/warn<br />4/error<br />5/fatal) <br />type: string | "2"/"info" |
| -mode | (execution mode: <br />0/interpreter<br />1/singlepass <br />2/multipass) <br />type: string | "0"/"interpreter" |
| -runTimes | (Set the number of execution runs) <br />type: uint32 | 1 |
| -withWasi | (Use WASI in statistics mode) <br />type: bool | true |
