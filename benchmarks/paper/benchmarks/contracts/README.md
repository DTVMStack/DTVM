# Contract Benchmarks (vm_benchmark)

The paper's **rich-semantic smart contract** microbenchmark: ERC20 / ERC721 / ERC1155 / Uniswap V2 / Fibonacci / Counter (plus ECDSA / Poseidon bytecode).

Source: `test/vm_benchmark/` in the contract-testbed repository. The reproduction notes were distilled from the experiment notes.

## Contents

| Path | Contents |
|------|----------|
| `bench_contract/` | Solidity contract sources (Uniswap V2 source is not included — see [`../../SOURCES.md`](../../SOURCES.md) for upstream links) |
| `bench_bytecode/` | prebuilt EVM / sol→wasm / C→wasm **hex artifacts** (no compile scripts) |
| runner source | not included (gtest driver, calldata assembly, Bazel BUILD — experiment archive only); methodology in `CALLS.md` / `REPRODUCE.md` |
| `CALLS.md` | per-case function under test, calldata, iteration counts |
| `REPRODUCE.md` | build, run, environment, and measurement methodology |
| `../../ENVIRONMENT.md` | 12-item environment/toolchain checklist (confirmed vs not recorded) |
| `MANIFEST.md` | file inventory and gtest case mapping |
| `SHA256SUMS` | integrity checksums |

## Archived / Not Archived

| Item | Status |
|------|--------|
| Solidity sources | ✅ |
| EVM / sol-wasm / C-wasm hex artifacts | ✅ (`c_*.hex` are artifacts only, **no C sources**) |
| Runner `bench.cpp` | exists in the archive; not included (depends on the source repo, cannot compile standalone) |
| sol→evm / sol→wasm compile commands | ❌ absent from the archive |
| C wasm sources | ❌ absent from the archive |
| Self-contained binary | ❌ requires building `test_vmbench` inside the contract-testbed repo |

## Index

- Reproduction steps → [`REPRODUCE.md`](REPRODUCE.md)
- Call parameters → [`CALLS.md`](CALLS.md)
- gtest ↔ hex mapping → [`MANIFEST.md`](MANIFEST.md)
