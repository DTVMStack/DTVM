# Benchmarks

Wasm test suites and rebuildable cases used by the paper experiments.

## Suite Status

| Directory | wasm count | Source | Build script | Status |
|-----------|-----------|--------|--------------|--------|
| `polybenchc/` | 30 | PolyBenchC-4.2.1 | `build.sh` (WASI clang) | **migrated**: wasm + rebuild docs |
| `contracts/` | — | Solidity + hex | testbed Bazel (see REPRODUCE) | **migrated**: sources / hex; runner source not included |
| `wapm/` | 21 | — | — | **migrated**: paper's 20 cases + fortune (zuk substitute) wasm + confs + SHA256 |
| `overflow/` | 1 | yes (C++) | yes | **migrated** |
| `fib/` | 3 | yes (C/Solidity) | — | **migrated**: standalone fib/md5 cases |

> The upstream archive also contained the libsodium (72-case) and wabench (22-case) suites and 9 non-paper WAPM cases (`main`, `python`, `spidermonkey`, `sqlite`, `wasm3`, `jq`, `jyt`, `pee`, `greg`); none were used in the paper and none were migrated.

## PolyBench Compilation (WASI clang)

- Source: [PolyBenchC-4.2.1](https://github.com/MatthiasJReisinger/PolyBenchC-4.2.1)
- Toolchain: WASI SDK `clang` (default `/opt/wasi-sdk/bin/clang`)
- Macros: `-DSMALL_DATASET -DDATA_TYPE_IS_INT -DPOLYBENCH_DUMP_ARRAYS`
- Details: `benchmarks/polybenchc/BUILD.md`

## Contract Microbenchmark

- Directory: `benchmarks/contracts/` (archive of `test/vm_benchmark` in the contract-testbed repo)
- Reproduction: inside the source repo, `sh build.sh release.vmbench 6 false 2`
- Details: `contracts/REPRODUCE.md`, `contracts/CALLS.md`

## Running

See `../scripts/run_polybench.sh` and `webassembly-testsuites/runtest_webassembly.py`.
