# Wasmer 7.1.0 (TTFI / overflow / fib mainline)

Shared version for PolyBench TTFI, WAPM TTFI, overflow, and fib(30). Three backends: **cranelift + singlepass + llvm**.

## Instrumentation Locations

- `lib/wasix/src/ttfi_report.rs`
- `lib/wasix/src/runtime/mod.rs` (compile timer around `Module::new`)
- `lib/wasix/src/state/builder.rs` (instantiate / guest execution timers)
- `lib/cli/src/commands/run/mod.rs` (readfile timer)

Example instrumented source: `/path/to/wasmer-7.1.0`

## LLVM 21 (required for the llvm backend)

wasmer 7.1 uses `llvm-sys-211` and needs **LLVM 21** (not the LLVM 18 from the paper-era 5.0.4).

```bash
tar -xf LLVM-21.1.8-Linux-X64.tar.xz -C ~
export LLVM_SYS_211_PREFIX=$HOME/LLVM-21.1.8-Linux-X64
$LLVM_SYS_211_PREFIX/bin/llvm-config --version   # 21.1.8
```

## Build

```bash
# default source path WASMER_SRC=/path/to/wasmer-7.1.0
LLVM_SYS_211_PREFIX=$HOME/LLVM-21.1.8-Linux-X64 ./build.sh
# artifact: out/bin/wasmer
```

Without LLVM 21 the script skips the `llvm` feature automatically and builds only `cranelift + singlepass`.

## Usage (TTFI)

```bash
./out/bin/wasmer run --cranelift  --cache-dir=/dev/null case.wasm
./out/bin/wasmer run --singlepass --cache-dir=/dev/null case.wasm
./out/bin/wasmer run --llvm       --cache-dir=/dev/null case.wasm
# expected stdout: Total compilation time: <ms> ms (<µs> µs)
```

Benchmark entry points: [`../../docs/POLYBENCH_TTFI_REPRODUCE.md`](../../docs/POLYBENCH_TTFI_REPRODUCE.md), [`../../docs/WAPM_TTFI_REPRODUCTION.md`](../../docs/WAPM_TTFI_REPRODUCTION.md).
