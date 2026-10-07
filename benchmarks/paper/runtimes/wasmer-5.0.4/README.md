# Wasmer 5.0.4 (historical)

Historical Wasmer pin for earlier PolyBench wall-clock `wasmer llvm` captures. Current paper experiments use Wasmer **7.1.0**; see [`../wasmer-7.1.0/`](../wasmer-7.1.0/).

## Build

```bash
./build.sh   # cranelift + singlepass by default; adds the llvm backend automatically when LLVM 18 is present
```

LLVM 18 setup:

```bash
export LLVM_SYS_180_PREFIX=/opt/clang+llvm-18.1.7-x86_64-linux-gnu-ubuntu-18.04
```

Artifact: `out/bin/wasmer` (covered by `.gitignore`).

## Docs

- [`BUILD.md`](BUILD.md) — instrumentation locations, benchmark flags

> Current paper experiments use Wasmer **7.1.0** (LLVM 21); see [`../wasmer-7.1.0/`](../wasmer-7.1.0/).
