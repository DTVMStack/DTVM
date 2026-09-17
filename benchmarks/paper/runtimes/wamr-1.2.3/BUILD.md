# WAMR 1.2.3 Build Notes

Upstream vanilla WAMR, used as the **`iwasm` baseline** for PolyBench and related experiments.

- Upstream: https://github.com/bytecodealliance/wasm-micro-runtime
- Target tag: **WAMR-1.2.3**
- Automation script: [`build.sh`](build.sh)

**Note**: this directory tracks upstream WAMR; it is **not** the same codebase as the DTVM fork (`runtimes/dtvm/`).

---

## Paper Baseline Practice

| Item | Version |
|------|---------|
| WAMR | **1.2.3** |
| LLVM (AOT) | **11.1.0** (per experiment notes; CMake typically points at an `llvm-11` package path) |

The PolyBench wasm side was presumably compiled with WASI-SDK **clang 11.0.0 / 14.0.3** (see `benchmarks/polybenchc/BUILD.md`).

---

## 1. Basic Build (CMake)

WAMR uses CMake. Standard flow:

```bash
git clone https://github.com/bytecodealliance/wasm-micro-runtime.git
cd wasm-micro-runtime
git checkout WAMR-1.2.3

cd product-mini/platforms/linux
mkdir build && cd build

cmake .. \
  -DWAMR_BUILD_INTERP=1 \
  -DWAMR_BUILD_FAST_JIT=1 \
  -DWAMR_BUILD_AOT=1 \
  -DWAMR_BUILD_LIBC_WASI=1

make -j$(nproc)
./iwasm --version
```

Or use the script in this directory:

```bash
cd runtimes/wamr-1.2.3
chmod +x build.sh
./build.sh all
# artifacts: out/iwasm, version.txt
```

---

## 2. Common CMake Options

| Option | Description |
|--------|-------------|
| `-DWAMR_BUILD_INTERP=1` | interpreter (**required for iwasm**) |
| `-DWAMR_BUILD_FAST_JIT=1` | Fast JIT (singlepass compiler) |
| `-DWAMR_BUILD_AOT=1` | AOT compiler (**requires LLVM**) |
| `-DWAMR_BUILD_LIBC_BUILTIN=1` | builtin libc |
| `-DWAMR_BUILD_LIBC_WASI=1` | WASI libc (**required to run PolyBench WASI wasm**) |
| `-DWAMR_BUILD_MULTI_MODULE=1` | multi-module support |

For the paper PolyBench baseline, enable at least **INTERP + LIBC_WASI**.

---

## 3. AOT Mode (requires LLVM)

```bash
# Ubuntu example (LLVM 11)
sudo apt-get install llvm-11 clang-11 llvm-11-dev

cd product-mini/platforms/linux/build
cmake .. \
  -DWAMR_BUILD_AOT=1 \
  -DWAMR_BUILD_INTERP=1 \
  -DWAMR_BUILD_LIBC_WASI=1 \
  -DLLVM_DIR=/usr/lib/llvm-11/lib/cmake/llvm

make -j$(nproc)
```

The experiment docs used **LLVM 11.1.0**; if only an `llvm-11` package is available, point `LLVM_DIR` at its cmake directory.

This repo's `build.sh` defaults to:

```bash
export LLVM_DIR=/usr/lib/llvm-11/lib/cmake/llvm
./build.sh all
```

If AOT is not needed, disable it:

```bash
WAMR_BUILD_AOT=0 ./build.sh all
```

---

## 4. Artifacts and Verification

| File | Description |
|------|-------------|
| `product-mini/platforms/linux/build/iwasm` | main executable |
| `out/iwasm` | `build.sh install` copies here |
| `version.txt` | `iwasm --version` output (**fill in after a real build**) |

Verify:

```bash
./out/iwasm --version
./out/iwasm benchmarks/polybenchc/atax.wasm   # run from the repo root or with an explicit path
```

---

## 5. Difference from DTVM (`runtimes/dtvm/`)

| | WAMR 1.2.3 (this dir) | DTVM (`runtimes/dtvm/`) |
|--|------------------------|--------------------------|
| Source | upstream bytecodealliance | fork |
| CLI | `iwasm` | `dtvm` |
| Role | paper baseline | paper main runtime |
| AOT LLVM | 11.1.0 | fork-specific config |

---

## 6. To Be Filled (after an actual build)

- [ ] `version.txt` (real `iwasm --version` output)
- [ ] `out/iwasm` binary or the recorded build-machine path
- [ ] full CMake log / `CMakeCache.txt` (optional, for auditing)
- [ ] checksum (`shasum -a 256 out/iwasm`)
