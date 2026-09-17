# Contract Benchmark Reproduction

Based on reproduction notes and `test/vm_benchmark/`.

This directory archives the **sources, hex artifacts, and methodology**; a full run still requires compiling the runner inside the contract-testbed repository.

## 1. Getting the Code

The contract bench runner (`test_vmbench`, a gtest binary) builds only inside the contract-testbed repository's `test/vm_benchmark/`, which is not included. This directory already contains all contract sources and hex artifacts (verifiable with `SHA256SUMS`); methodology and parameters are in `CALLS.md`. External readers can reproduce the wasm-side experiments; the EVM comparison part is documented for methodology reference only.

## 2. Building test_vmbench (source repository)

At the root of the contract-testbed repository:

```bash
sh build.sh release.vmbench 6 false 2
```

Output: `test_vmbench` (gtest binary, depends on the EVM/DTVM stack in that repository).

DTVM build macros used in the paper:

```
ZEN_ENABLE_JIT
ZEN_ENABLE_SINGLEPASS_JIT
ZEN_ENABLE_DWASM
ZEN_ENABLE_CHECKED_ARITHMETIC
```

## 3. Running

Single case:

```bash
./test_vmbench --gtest_filter=VMBenchTest.Erc20Evm
./test_vmbench --gtest_filter=VMBenchTest.SolErc20Wasm
```

EVM vs DTVM (sol→wasm) comparison:

```bash
./test_vmbench --gtest_filter=VMBenchTest.Erc20Evm:VMBenchTest.SolErc20Wasm
```

### Paper Cases (gtest names)

| Workload | EVM | sol→wasm | C→wasm |
|----------|-----|----------|--------|
| ERC20 `transfer` | `Erc20Evm` | `SolErc20Wasm` | `CErc20Wasm` (may be commented out on the branch) |
| ERC721 `transferFrom` | `Erc721Evm` | `SolErc721Wasm` | — |
| ERC1155 `safeTransferFrom` | `Erc1155Evm` | `SolErc1155Wasm` | — |
| Uniswap V2 `swapExactTokensForTokens` | `UniswapV2Evm` | `SolUniswapV2Wasm` | — |
| Fibonacci | `FibEvm` | `SolFibWasm` | `CFibWasm` |
| Counter `increase` | `CounterEvm` | `SolCounterWasm` | — |
| ECDSA R1 verify | `ECDSAEvm` | `SolECDSAWasm` | — |
| Poseidon | `PoseidonEvm` | `SolPoseidonWasm` | — |
| Merkle Proof verify | `MerkleProofEvm` | `SolMerkleProofWasm` | — |
| Generative NFT generate | `GenerativeNFTEvm` | `SolGenerativeNFTWasm` | — |

Call details: [`CALLS.md`](CALLS.md).

## 4. Experiment Environment (paper)

**Test machine (confirmed in experiment notes):** compute-optimized **c7, 8C16G**, **Intel(R) Xeon(R) Platinum 8369B CPU @ 2.70GHz**

The full 12-item environment checklist is in [`ENVIRONMENT.md`](../../ENVIRONMENT.md). Hardware/CPU items:

| Item | Value | Note |
|------|-------|------|
| Machine | compute-optimized **c7, 8C16G** | experiment notes (0422 archive) |
| CPU | **Intel Xeon Platinum 8369B @ 2.70GHz** | experiment notes |
| Workload shape | **serial** microbenchmark | notes: "1C is enough"; no pinning recorded |
| OS / Kernel | **not recorded** | only known to be Linux (runner reads `/proc/cpuinfo`) |
| Docker / dedicated host / governor / background load | **not recorded** | — |
| Observed frequency | `/proc/cpuinfo` → **cpu MHz ≈ 2699.998** | not a manual cpufreq step |
| Turbo Boost | **off** | experiment notes + archived runner-source comment |
| Cache clearing | **not recorded** | State / Module LRU caches **are reused** during measurement |
| Iterations | **10000** per measured tx, average cycles | experiment notes |

## 5. Measurement Methodology

- **`rdtsc`** records CPU cycles, converted to time via the CPU frequency.
- Measurement target: **pure VM execute after instance creation** (intended to exclude load-module / create-instance; the exact boundaries are the `__rdtsc()` sites in the archived runner source).
- EVM path: `evmone`; wasm contract path: DTVM **MultipassMode**.
- Modules are LRU-cached by **code_hash + spec_version** (size=32); each call still **creates a new Instance**.
- The ERC20 measured transfer uses `MockedExecute` (unlike `Execute` in other cases).
- Mock state: `ReadAccount` only initializes the `from` balance; `ReadStorage` returns empty; `EVMContext` is the default `{}`.

## 6. raw_data Mapping

| Output | Path |
|--------|------|
| Raw cycles samples | per-iteration `.time` files are not included |
| Figures | not included (regenerate from fresh benchmark output) |

## 7. Known Gaps

- **No** C sources for `c_erc20_wasm` / `c_fib_wasm` (only `.hex` artifacts).
- `test_vmbench` depends on the source repository and cannot be built standalone here.

## 8. Wasm Compilation (Merkle Proof / Generative NFT)

The sol→wasm compilation for the newer Merkle Proof and Generative NFT cases used **DTVM_SolSDK v0.1.1**:

```bash
# Install DTVM_SolSDK (prebuilt package)
tar xzf DTVM_SolSDK-v0.1.1-ubuntu22.04.tar.gz
export YUL2WASM=DTVM_SolSDK-26844a8-Linux/yul2wasm

# MerkleProof
solc --ir --optimize-yul -o /tmp/merkle_yul --overwrite MerkleProof.sol
$YUL2WASM --input /tmp/merkle_yul/MerkleProof.yul --output MerkleProof.wasm

# GenerativeNFT
solc --ir --optimize-yul -o /tmp/gennft_yul --overwrite GenerativeNFT.sol
$YUL2WASM --input /tmp/gennft_yul/GenerativeNFT.yul --output GenerativeNFT.wasm
```

## 9. Contract Microbenchmark Results (evmone 0.21.0 vs DTVM)

Environment: Linux x86_64 CentOS (c7 8C16G, Xeon 8369B), evmone 0.21.0 (local source build), DTVM multipass JIT.
Build command: `sh build.sh release.vmbench 6 false 2` (`OP_VM_TYPE=2`, i.e. multipass).
Each measured tx repeated **10000** times; average CPU cycles (`rdtsc`) converted to time.

| Workload | evmone 0.21.0 (EVM) | DTVM (sol→wasm) | DTVM/evmone |
|----------|--------------------:|----------------:|:-----------:|
| ERC20 transfer | 19.67 us | 25.11 us | 0.78x |
| ERC721 transferFrom | — | — | — |
| ERC1155 safeTransfer | — | — | — |
| UniswapV2 swap | — | — | — |
| ECDSA verify | 1322.46 us | 14.31 us | **92.4x** |
| Poseidon hash | — | — | — |
| Fibonacci(30) | 180,385 us | 67,853 us | **2.66x** |
| Counter increase | 8.72 us | 16.13 us | 0.54x |
| **Merkle Proof (MiMC)** | 2268.45 us | 565.36 us | **4.01x** |
| **Generative NFT (MiMC sponge)** | 1944.97 us | 657.63 us | **2.96x** |

> DTVM/evmone > 1 means DTVM is faster.
>
> **Merkle Proof** uses MiMC hashing (91-round x^7 mod P S-box), 10 verification rounds, 20-node proofs each.
> The mix of `addmod`/`mulmod`/`keccak256` plus loop control flow favors the DTVM JIT.
>
> **Generative NFT** uses an MiMC sponge for deterministic on-chain attribute generation, 8 layers with 2 sponge absorptions each — again dominated by compute-heavy cryptographic primitives.
>
> Compute-dense cases like ECDSA and Fibonacci show the largest DTVM advantage (92x / 2.7x).
> Simple contracts such as ERC20/Counter favor evmone because wasm carries extra serialization/dispatch overhead.
