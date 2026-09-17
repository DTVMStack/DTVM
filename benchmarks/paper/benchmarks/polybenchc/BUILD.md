# PolyBench/C 4.2.1 — WASM Build Notes

## Source

- Repository: [MatthiasJReisinger/PolyBenchC-4.2.1](https://github.com/MatthiasJReisinger/PolyBenchC-4.2.1)
- Version: **PolyBench/C 4.2.1**

`build.sh prepare` clones it into `build/PolyBenchC-4.2.1/` automatically.

## Relationship to the Archived `.wasm` Files

This directory already archives the **30** `.wasm` binaries actually used at the time (see `MANIFEST.md`, `SHA256SUMS`).

Binary analysis of the archived wasm:

| Trait | Archived wasm | `build.sh wasm` |
|-------|---------------|-----------------|
| Entry | `_start` / `main` (WASI) | `_start` / `main` (WASI) |
| Output format | `==BEGIN DUMP_ARRAYS==` | `-DPOLYBENCH_DUMP_ARRAYS` |
| Toolchain | clang 11.0.0 / 14.0.3 + WASI | **WASI SDK clang** |
| Case count | **30** | full `utilities/benchmark_list` |

After rebuilding, compare against `SHA256SUMS` to check whether the output matches the paper wasm (clang / wasi-sdk minor-version differences may change the hashes).

---

## 1. Build Environment

| Component | Purpose |
|-----------|---------|
| **WASI SDK clang** | main WASM toolchain (`/opt/wasi-sdk/bin/clang`) |
| GCC | native comparison build |
| Emscripten | optional alternative toolchain |
| git | fetch PolyBenchC-4.2.1 |

---

## 2. Macros and Options

### Dataset Size

WASM memory is limited, so **`SMALL_DATASET`** is used.

Alternatives: `-DMINI_DATASET`, `-DSMALL_DATASET`, `-DMEDIUM_DATASET`, `-DLARGE_DATASET`, `-DEXTRALARGE_DATASET`

### Data Type

```bash
-DDATA_TYPE_IS_INT
```

### Output Format (matches the archived wasm)

```bash
-DPOLYBENCH_DUMP_ARRAYS
```

### WASI Compatibility

```bash
-D_WASI_EMULATED_PROCESS_CLOCKS
```

### Linker Exports

```bash
-Wl,--export=__heap_base -Wl,--export=__data_end -Wl,--export=malloc -Wl,--export=free
```

### SIMD Disabled (native GCC comparison)

```bash
NO_SIMD="-mno-mmx -mno-sse2 ... -mno-avx512vbmi"
# Note: do NOT use -mno-sse — it breaks the build
```

---

## 3. Compile Commands

### WASM (clang, main path)

```bash
WASI_CLANG=/opt/wasi-sdk/bin/clang

$WASI_CLANG -O3 -I utilities -I linear-algebra/solvers/mvt \
  -DSMALL_DATASET -DDATA_TYPE_IS_INT -DPOLYBENCH_DUMP_ARRAYS \
  -D_WASI_EMULATED_PROCESS_CLOCKS \
  utilities/polybench.c linear-algebra/solvers/mvt/mvt.c \
  -Wl,--export=__heap_base -Wl,--export=__data_end \
  -Wl,--export=malloc -Wl,--export=free \
  -o mvt.wasm
```

### Native (GCC comparison)

```bash
GCC_PARGS="-O3 -I utilities -DPOLYBENCH_TIME -DSMALL_DATASET -DDATA_TYPE_IS_INT $NO_SIMD -lm"
gcc $GCC_PARGS -o mvt_native linear-algebra/solvers/mvt/mvt.c utilities/polybench.c
```

### Optional: Emscripten

```bash
emcc -O3 -s WASM=1 -DSMALL_DATASET -DDATA_TYPE_IS_INT -DPOLYBENCH_DUMP_ARRAYS \
     -I utilities -I linear-algebra/solvers/mvt \
     -o mvt.wasm \
     linear-algebra/solvers/mvt/mvt.c utilities/polybench.c
```

---

## 4. Using `build.sh`

```bash
chmod +x build.sh

# clone the sources
./build.sh prepare

# WASI clang build of the full benchmark_list
export WASI_CLANG=/opt/wasi-sdk/bin/clang
./build.sh wasm

# Native + WASM
./build.sh all

# single case
./build.sh one linear-algebra/solvers/mvt/mvt.c

# emcc example
./build.sh emcc
```

Output directory: `out/` (override with `OUT_DIR`).

---

## 5. Archived Case List (30)

```
2mm, 3mm, adi, atax, bicg, cholesky, correlation, covariance,
deriche, doitgen, durbin, fdtd-2d, floyd-warshall, gemm, gemver,
gesummv, gramschmidt, heat-3d, jacobi-2d, jacobi_1d, lu, ludcmp,
mvt, nussinov, seidel-2d, symm, syr2k, syrk, trisolv, trmm
```

---

## 6. Notes

1. **Entry point**: WASI clang uses `_start`/`main`; no `apply` export is needed.
2. **Memory**: `SMALL_DATASET` controls the dataset size.
3. **Floating point**: `-DDATA_TYPE_IS_INT` is recommended.
4. **wasi-sdk version**: the archived wasm carries clang 11.0.0 / 14.0.3 traces; pin the same wasi-sdk version when reproducing.

---

## 7. Verification

```bash
shasum -a 256 out/*.wasm
diff <(awk '{print $1}' SHA256SUMS | sort) <(shasum -a 256 out/*.wasm | awk '{print $1}' | sort)

wasm-objdump -x out/mvt.wasm | rg export

wasmtime run out/mvt.wasm
iwasm out/mvt.wasm
```

---

## Appendix: `polybench-wasm-patch.h`

[`polybench-wasm-patch.h`](polybench-wasm-patch.h) is kept for reference (the older `ftrace` / `apply`-entry patching scheme). **The current `build.sh` clang/WASI path does not use this patch.**
