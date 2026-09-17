# PolyBench/C (30 cases)

The **PolyBench/C 4.2.1** suite. This directory contains the wasm binaries actually used in the paper plus the **WASI clang** rebuild flow.

## Source

- [MatthiasJReisinger/PolyBenchC-4.2.1](https://github.com/MatthiasJReisinger/PolyBenchC-4.2.1)
- Build notes: [`BUILD.md`](BUILD.md)
- Automation: [`build.sh`](build.sh)

## Case List (30)

```
2mm, 3mm, adi, atax, bicg, cholesky, correlation, covariance,
deriche, doitgen, durbin, fdtd-2d, floyd-warshall, gemm, gemver,
gesummv, gramschmidt, heat-3d, jacobi-2d, jacobi_1d, lu, ludcmp,
mvt, nussinov, seidel-2d, symm, syr2k, syrk, trisolv, trmm
```

## Archived (the wasm actually used)

- `*.wasm` (30) + `SHA256SUMS`
- `*.wasm.expected` (11), test configs, `runtest_polybench.sh`

## Rebuild (WASI clang)

```bash
export WASI_CLANG=/opt/wasi-sdk/bin/clang
./build.sh prepare
./build.sh wasm
```

Compile macros: `-O3 -DSMALL_DATASET -DDATA_TYPE_IS_INT -DPOLYBENCH_DUMP_ARRAYS -D_WASI_EMULATED_PROCESS_CLOCKS`

## Running the Tests

```bash
./runtest_webassembly.py -r iwasm -s polybenchc
./runtest_webassembly.py -r wasmtime -s polybenchc
./runtest_webassembly.py -r dtvm -s polybenchc
```
