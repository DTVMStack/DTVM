# Source and License Notes

The material in this directory was curated from an experiment archive. This file records the provenance and upstream licenses.

## Source → This Repository

| Path here | Archive source | Notes |
|-----------|---------------|-------|
| `runtimes/dtvm/` | DTVM source repository | the paper baseline fork; not WAMR 1.2.3 |
| `benchmarks/polybenchc/`, `benchmarks/wapm/` (wasm) | `webassembly-testsuites` repo `case/benchmark/`, `case/wapm/` | prebuilt wasm of public PolyBench/C and WAPM workloads |
| `benchmarks/contracts/` | contract-testbed repo `test/vm_benchmark/` | contract sources and hex artifacts; runner source not included |
| `benchmarks/overflow/`, `benchmarks/fib/` | experiment archive | Fig. 7 workloads |

## Upstream Public Sources

| Content | Upstream | License |
|---------|----------|---------|
| `benchmarks/polybenchc/` | PolyBench/C 4.2.1 (compiled to wasm with WASI-SDK) | PolyBench license |
| `benchmarks/wapm/*.wasm` | public WAPM packages (wapm.io) | per-package licenses |
| `benchmarks/wapm/fonts/`, `lib/` | WAPM package runtime dependencies | same as above |
| `bench_contract/erc20|721|1155` etc. | OpenZeppelin Contracts | MIT |
| Uniswap V2 contracts (source not included) | https://github.com/Uniswap/v2-core + https://github.com/Uniswap/v2-periphery | **GPL-3.0-or-later**; the `uniswapv2_*` hex in `bench_bytecode/` are their prebuilt artifacts |
| `bench_contract/ecdsa/` (P256 etc.) | OpenZeppelin / community implementations | MIT |
| `runtimes/wasmtime-*`, `wasmer-*`, `wamr-*` | upstream official releases / tags | respective licenses |
| `benchmarks/contracts/bench_bytecode/*.hex` | prebuilt artifacts of the sources above | follow the source license |

## Gaps (absent from the archive as well)

- Upstream WAMR 1.2.3 checkout (fetch the official tag yourself)
- Wasmtime 31.0.0 binary (use the official tarball; see `runtimes/wasmtime-31.0.0/BUILD.md`)
- Contract sol→evm / sol→wasm compile commands (only prebuilt hex exist)
- C sources for `c_erc20_wasm` / `c_fib_wasm`
- Sources for standalone wasm such as `fib_no_contract.c.wasm`
- The DTVM binary (build per `runtimes/dtvm/BUILD.md`)
