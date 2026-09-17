# PolyBench/C Manifest

Source: `webassembly-testsuites/case/benchmark/polybenchc/` (testsuite repository, commit `b779fda`, 2023-04-12)

## Contents

| Type | Count |
|------|-------|
| `.wasm` | 30 |
| `.wasm.expected` | 11 |
| `*_config.py` | 9 |
| `config.py` | 1 |
| `iwasm.conf` | 1 |
| `runtest_polybench.sh` | 1 (legacy script; paths are outdated) |
| `BUILD.md`, `build.sh` | WASI **clang** rebuild flow |
| `polybench-wasm-patch.h` | legacy patching scheme, for reference only (unused by the clang path) |

## Source Version

- **PolyBench/C 4.2.1**
- GitHub: https://github.com/MatthiasJReisinger/PolyBenchC-4.2.1

## Compile Macros (WASI clang)

```
-O3 -DSMALL_DATASET -DDATA_TYPE_IS_INT -DPOLYBENCH_DUMP_ARRAYS -D_WASI_EMULATED_PROCESS_CLOCKS
-Wl,--export=__heap_base -Wl,--export=__data_end -Wl,--export=malloc -Wl,--export=free
-DPOLYBENCH_TIME   # native GCC comparison build
```

## Case List (30)

```
2mm.wasm          3mm.wasm          adi.wasm          atax.wasm
bicg.wasm         cholesky.wasm     correlation.wasm covariance.wasm
deriche.wasm      doitgen.wasm      durbin.wasm       fdtd-2d.wasm
floyd-warshall.wasm gemm.wasm       gemver.wasm       gesummv.wasm
gramschmidt.wasm  heat-3d.wasm      jacobi-2d.wasm    jacobi_1d.wasm
lu.wasm           ludcmp.wasm       mvt.wasm          nussinov.wasm
seidel-2d.wasm    symm.wasm         syr2k.wasm        syrk.wasm
trisolv.wasm      trmm.wasm
```

## Integrity

See `SHA256SUMS` in this directory.

## Notes

- **Archived wasm**: the 30 binaries actually used at the time (WASI/clang; see `SHA256SUMS`).
- **Rebuild**: `build.sh` uses the WASI SDK **clang**; compare hashes after rebuilding.
