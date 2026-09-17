# Contract Call Parameters

Extracted from the archived runner source `test/vm_benchmark/bench.cpp`. All cases share the same **setup**, then run a **10000-iteration** measured loop (`repeat_times = 10000`).

## Common Setup

| Item | Value |
|------|-------|
| `from` | `0x095e7baea6a6c7c4c2dfeb977efac326af552d87` |
| Initial balance | `1 ether` |
| setup tx1 | transfer 100 wei → `0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b` (nonce 0) |
| setup tx2 | contract create; deploy bytecode from `bench_bytecode/*.hex` (nonce 1) |
| Contract address (nonce 1) | `0xb88de88b35ecbf3c141e3caae2baf35834d18f63` |
| gas | `21000000` for most setup/measurement txs; `0xFFFFFFFFFFFFFE` for the Fib measurement tx |
| gas_price | `1` |

Extra fixed addresses for Uniswap (deployed in nonce order):

| Contract | Address |
|----------|---------|
| Factory | `0xb88de88b35ecbf3c141e3caae2baf35834d18f63` |
| Router | `0x5d35480c6e7f8952363fa280a0a96906da981f63` |
| Token0 | `0x5b5bd343a12fb42c62390aff6340b59947b60263` |
| Token1 | `0xa2b91fd595c51dec3fe42be1fbf3bfcb3bc9e4ed` |

## Measured Calls (counted in cycles)

| Case | Function | Selector | Arguments / calldata | Execute API |
|------|----------|----------|----------------------|-------------|
| ERC20 | `transfer(address,uint256)` | `0xa9059cbb` | to=`0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97`, amount=`1` | `MockedExecute` |
| ERC721 | `transferFrom(address,address,uint256)` | `0x23b872dd` | from=above, to=`0x4838b106...`, tokenId=loop var `i` | `Execute` |
| ERC1155 | `safeTransferFrom(...)` | `0xf242432a` | from, to, id=`1`, amount=`1`, data=`0x` | `Execute` |
| Fib | `fibonacci(uint256)` | `0x61047ff4` | n=`20` (`0x14`) | `Execute` |
| Counter | `increase()` | `0xe8927fbc` | none | `Execute` |
| Uniswap V2 | `swapExactTokensForTokens(...)` | `0x38ed1739` | amountIn=`10`, minOut=`0`, path token0→token1, to=from, deadline=`0` | `Execute` |
| ECDSA | `verify(...)` | `0xade9ec41` | see `TestECDSA` | `Execute` |
| Poseidon | `calc(...)` | `0xeb6c5b9e` | see `TestPoseidonHash` | `Execute` |
| Merkle Proof | `benchmark()` | `0x8903c5a2` | none; builds and verifies a 10-level proof internally | `Execute` |
| Generative NFT | `generate(uint256)` | `0x4a7dd523` | tokenId=`1` | `Execute` |

## Setup Calls (not counted in the cycles loop)

| Case | Function | Selector | Notes |
|------|----------|----------|-------|
| ERC20 | `mint(address,uint256)` | `0x40c10f19` | minted once after deploy |
| ERC721 | `mint(address)` | `0x6a627842` | minted **10000 times** after deploy (warmup) |
| ERC1155 | `mint(...)` | `0x731133e9` | minted **once** after deploy |
| Uniswap | `createPair` / `addLiquidity` / `approve` / `getReserves` etc. | various | see `TestUniswapV2`; full DEX initialization before swap |

## gtest ↔ Bytecode Files

| gtest | hex constant / file |
|-------|---------------------|
| `Erc20Evm` | `bench_bytecode/erc20_evm.hex` |
| `SolErc20Wasm` | `bench_bytecode/sol_erc20_wasm.hex` |
| `CErc20Wasm` | `bench_bytecode/c_erc20_wasm.hex` |
| `Erc721Evm` | `bench_bytecode/erc721_evm.hex` |
| `SolErc721Wasm` | `bench_bytecode/sol_erc721_wasm.hex` |
| `Erc1155Evm` | `bench_bytecode/erc1155_evm.hex` |
| `SolErc1155Wasm` | `bench_bytecode/sol_erc1155_wasm.hex` |
| `UniswapV2Evm` | `uniswapv2_factory_evm.hex` + `uniswapv2_router_evm.hex` + `uniswapv2_erc20_evm.hex` |
| `SolUniswapV2Wasm` | `sol_uniswapv2_factory_wasm.hex` + `sol_uniswapv2_router_wasm.hex` + `sol_erc20_wasm.hex` |
| `FibEvm` | `bench_bytecode/fib_evm.hex` |
| `SolFibWasm` | `bench_bytecode/sol_fib_wasm.hex` |
| `CFibWasm` | `bench_bytecode/c_fib_wasm.hex` |
| `CounterEvm` | `bench_bytecode/counter_evm.hex` |
| `SolCounterWasm` | `bench_bytecode/sol_counter_wasm.hex` |
| `MerkleProofEvm` | `bench_bytecode/merkle_evm.hex` |
| `SolMerkleProofWasm` | `bench_bytecode/sol_merkle_wasm.hex` |
| `GenerativeNFTEvm` | `bench_bytecode/generative_nft_evm.hex` |
| `SolGenerativeNFTWasm` | `bench_bytecode/sol_generative_nft_wasm.hex` |

Full list: [`MANIFEST.md`](MANIFEST.md).
