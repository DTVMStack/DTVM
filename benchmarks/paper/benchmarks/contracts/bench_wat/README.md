# Contract Benchmark WAT Sources

WebAssembly text (`.wat`) forms of the contract microbenchmark modules used by
the sol→wasm experiments. Only the text form is stored here: it is diffable and
human-reviewable, while the binary `.wasm` output (~0.7 MB total) is a build
artifact and is ignored by [`.gitignore`](.gitignore).

Source Solidity is in [`../bench_contract/`](../bench_contract); prebuilt EVM /
wasm deployment blobs are in [`../bench_bytecode/`](../bench_bytecode); call
parameters and methodology are in [`../CALLS.md`](../CALLS.md) and
[`../REPRODUCE.md`](../REPRODUCE.md).

## Inventory (15 modules)

All modules import only from the DTVM/wasm contract host module `env`
(`getCallDataSize`, `callDataCopy`, `getCallValue`, `finish`, `revert`, …), the
same ABI the contract testbed runner uses.

| `.wat` | module bytes | Case | EVM counterpart | Matches `bench_bytecode/*_wasm.hex` |
|--------|-------------:|------|-----------------|-------------------------------------|
| `counter.wat` | 7,233 | Counter `increase()` (`SolCounterWasm`) | `counter_evm.hex` | ✅ `sol_counter_wasm.hex` |
| `erc20.wat` | 32,458 | ERC20 `transfer` (`SolErc20Wasm`) | `erc20_evm.hex` | ❌ newer build |
| `uniswap_v2_token.wat` | 32,458 | Uniswap V2 pair token | `uniswapv2_erc20_evm.hex` | ❌ newer build |
| `erc721.wat` | 49,076 | ERC721 `transferFrom` (`SolErc721Wasm`) | `erc721_evm.hex` | ✅ `sol_erc721_wasm.hex` |
| `erc1155_single.wat` | 59,868 | ERC1155 `safeTransferFrom` (`SolErc1155Wasm`) | `erc1155_evm.hex` | ✅ `sol_erc1155_wasm.hex` |
| `erc1155_batch2.wat` | 59,868 | ERC1155 `safeBatchTransferFrom` (2 ids) | `erc1155_evm.hex` | ✅ `sol_erc1155_wasm.hex` |
| `fibonacci_30.wat` | 9,531 | Fibonacci(30) (`SolFibWasm`) | `fib_evm.hex` | ✅ `sol_fib_wasm.hex` |
| `ecdsa_p256.wat` | 44,125 | P256 verify (`SolECDSAWasm`) | `ecdsa_evm.hex` | ❌ newer build |
| `poseidon.wat` | 72,189 | Poseidon hash (`SolPoseidonWasm`) | `poseidon_evm.hex` | ✅ `sol_poseidon_wasm.hex` |
| `merkle_proof.wat` | 15,689 | Merkle proof verify (`SolMerkleProofWasm`) | `merkle_evm.hex` | ❌ newer build |
| `generative_nft.wat` | 11,577 | Generative NFT (`SolGenerativeNFTWasm`) | `generative_nft_evm.hex` | ❌ newer build |
| `uniswap_v2_factory.wat` | 124,154 | Uniswap V2 Factory (`SolUniswapV2Wasm`) | `uniswapv2_factory_evm.hex` | ❌ newer build |
| `uniswap_v2_router.wat` | 141,380 | Uniswap V2 Router (`SolUniswapV2Wasm`) | `uniswapv2_router_evm.hex` | ❌ newer build |
| `rpow_pilot.wat` | 13,217 | fixed-point `rpow` micro case | — | — |
| `uniswap_v3_tickmath_pilot.wat` | 30,224 | Uniswap V3 TickMath micro case | — | — |

Notes:

- `erc20.wat` and `uniswap_v2_token.wat` are byte-identical modules (the Uniswap
  pair token uses the same OpenZeppelin ERC20), likewise `erc1155_single.wat`
  and `erc1155_batch2.wat` (the batch entry point shares the module).
- "Matches" means the generated `.wasm` equals the `bench_bytecode/*_wasm.hex`
  payload after dropping that blob's 4-byte big-endian module-length prefix
  (e.g. `00001c41` = 7,233 for Counter). For the other modules the archived hex
  payload and these modules are different builds of the same sources (sizes and
  hashes differ), so treat the WAT as the current build and the hex blobs as the
  paper-time artifacts.
- The two `*_pilot` cases are contract-shaped microbenchmarks that have no EVM
  counterpart in `../bench_bytecode/`.
- Integrity: the checksums of these `.wat` files are in
  [`../SHA256SUMS`](../SHA256SUMS). Binary `.wasm` files are not listed there —
  they are tracked by git-lfs, whose object ids are content SHA-256 (verify with
  `git lfs fsck`).

## Rebuilding `.wasm` from `.wat`

Requires [WABT](https://github.com/WebAssembly/wabt) (`wat2wasm`). The
`--enable-annotations` flag is required: every module carries an
`(@custom "target_features" …)` section, and `poseidon.wat` additionally carries
`(@custom "name" …)`.

```bash
# single module
wat2wasm --enable-annotations erc20.wat -o erc20.wasm

# all modules in this directory
for f in *.wat; do
  wat2wasm --enable-annotations "$f" -o "${f%.wat}.wasm"
done
```

Verified with WABT 1.0.36:

- All 15 modules assemble and validate.
- 14 of 15 reproduce the original `.wasm` byte-for-byte.
- `poseidon.wasm` re-encodes to 71,851 bytes instead of 72,189: the original
  binary declares one local group per type run (28 groups), and WABT merges
  adjacent same-type groups (2 groups). The instruction stream and local indices
  are unchanged, so the module is semantically identical.
- `wasm2wat --enable-annotations` on each rebuilt `.wasm` reproduces the
  checked-in `.wat` exactly.

If you need the byte-identical original for `poseidon`, take
`../bench_bytecode/sol_poseidon_wasm.hex` (minus the 4-byte prefix) or
`../bench_contract/poseidon/Poseidon.wasm`.

## How these modules were produced

The upstream pipeline is the one documented in
[`../REPRODUCE.md`](../REPRODUCE.md) §8:

```bash
# 1. Solidity -> Yul
solc --ir --optimize-yul -o /tmp/yul --overwrite ERC20.sol

# 2. Yul -> wasm (DTVM_SolSDK)
yul2wasm --input /tmp/yul/ERC20.yul --output ERC20.wasm

# 3. wasm -> wat (this directory)
wasm2wat --enable-annotations ERC20.wasm -o ERC20.wat
```

`bench_bytecode/*_wasm.hex` holds the deployment blob: a 4-byte big-endian
module length followed by the module bytes.
