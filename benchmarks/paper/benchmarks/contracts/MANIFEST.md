# Manifest

## bench_bytecode/*.hex (25)

| File | Purpose |
|------|---------|
| `erc20_evm.hex` | ERC20 EVM deployment bytecode |
| `sol_erc20_wasm.hex` | ERC20 sol→wasm |
| `c_erc20_wasm.hex` | ERC20 C→wasm (**hex only, no C source**) |
| `erc721_evm.hex` | ERC721 EVM |
| `sol_erc721_wasm.hex` | ERC721 sol→wasm |
| `erc1155_evm.hex` | ERC1155 EVM |
| `sol_erc1155_wasm.hex` | ERC1155 sol→wasm |
| `uniswapv2_factory_evm.hex` | Uniswap V2 Factory EVM |
| `uniswapv2_router_evm.hex` | Uniswap V2 Router EVM |
| `uniswapv2_erc20_evm.hex` | Uniswap pair token EVM |
| `sol_uniswapv2_factory_wasm.hex` | Factory sol→wasm |
| `sol_uniswapv2_router_wasm.hex` | Router sol→wasm |
| `fib_evm.hex` | Fibonacci EVM |
| `sol_fib_wasm.hex` | Fibonacci sol→wasm |
| `c_fib_wasm.hex` | Fibonacci C→wasm (**hex only, no C source**) |
| `counter_evm.hex` | Counter EVM |
| `sol_counter_wasm.hex` | Counter sol→wasm |
| `ecdsa_evm.hex` | ECDSA EVM |
| `sol_ecdsa_wasm.hex` | ECDSA sol→wasm |
| `poseidon_evm.hex` | Poseidon EVM |
| `sol_poseidon_wasm.hex` | Poseidon sol→wasm |
| `merkle_evm.hex` | Merkle Proof EVM |
| `sol_merkle_wasm.hex` | Merkle Proof sol→wasm |
| `generative_nft_evm.hex` | Generative NFT EVM |
| `sol_generative_nft_wasm.hex` | Generative NFT sol→wasm |

## bench_contract/ Sources

| Directory / file | Description |
|------------------|-------------|
| `erc20/erc20.sol` | OpenZeppelin ERC20 + mint |
| `erc721/erc721.sol` | OpenZeppelin ERC721 + mint |
| `erc1155/erc1155.sol` | OpenZeppelin ERC1155 + mint |
| `counter/counter.sol` | increase / decrease |
| `fibonacci/fib.sol` | recursive fibonacci |
| `uniswapv2/` (not included) | Factory / Router / Pair / ERC20 + libraries; upstream https://github.com/Uniswap/v2-core and https://github.com/Uniswap/v2-periphery (GPL-3.0-or-later); the bench uses the prebuilt hex under `bench_bytecode/` |
| `ecdsa/` | P256 verify and its dependencies |
| `poseidon/poseidon.sol` | Poseidon hash |
| `merkle/MerkleProof.sol` | 10-level keccak256 Merkle proof verification |
| `generative_nft/GenerativeNFT.sol` | on-chain SVG generative art (8 circles, keccak256 PRNG) |

> The ERC721/1155/20 `.sol` files reference `@openzeppelin/contracts`; recompiling them requires resolving that dependency in the testbed build environment.

## bench_wat/*.wat (15)

WAT text forms of the sol→wasm modules. Details and rebuild commands:
[`bench_wat/README.md`](bench_wat/README.md).

| File | Corresponding case / hex |
|------|--------------------------|
| `counter.wat` | Counter → `bench_bytecode/sol_counter_wasm.hex` |
| `erc20.wat` | ERC20 → `bench_bytecode/sol_erc20_wasm.hex` (newer build) |
| `uniswap_v2_token.wat` | Uniswap pair token (same module bytes as `erc20.wat`) |
| `erc721.wat` | ERC721 → `bench_bytecode/sol_erc721_wasm.hex` |
| `erc1155_single.wat` | ERC1155 `safeTransferFrom` → `bench_bytecode/sol_erc1155_wasm.hex` |
| `erc1155_batch2.wat` | ERC1155 `safeBatchTransferFrom` (same module bytes as `erc1155_single.wat`) |
| `fibonacci_30.wat` | Fibonacci → `bench_bytecode/sol_fib_wasm.hex` |
| `ecdsa_p256.wat` | ECDSA P256 → `bench_bytecode/sol_ecdsa_wasm.hex` (newer build) |
| `poseidon.wat` | Poseidon → `bench_bytecode/sol_poseidon_wasm.hex` |
| `merkle_proof.wat` | Merkle proof → `bench_bytecode/sol_merkle_wasm.hex` (newer build) |
| `generative_nft.wat` | Generative NFT → `bench_bytecode/sol_generative_nft_wasm.hex` (newer build) |
| `uniswap_v2_factory.wat` | Uniswap V2 Factory → `bench_bytecode/sol_uniswapv2_factory_wasm.hex` (newer build) |
| `uniswap_v2_router.wat` | Uniswap V2 Router → `bench_bytecode/sol_uniswapv2_router_wasm.hex` (newer build) |
| `rpow_pilot.wat` | fixed-point `rpow` micro case (no hex) |
| `uniswap_v3_tickmath_pilot.wat` | Uniswap V3 TickMath micro case (no hex) |

## runner/ (not included; experiment archive only)

| File | Description |
|------|-------------|
| `bench.cpp` | gtest implementation (~2456 lines): mock state, calldata assembly, rdtsc timing |
| `gen_deploy.py` | hex → `gen_deploy.h` generator |
| `BUILD` | original `test/vm_benchmark/` Bazel BUILD |

## Raw-output Naming

The runner writes one `.time` sample file per case under `raw_data/contracts/` (not included here). The naming convention is:

| gtest prefix | `.time` filename |
|--------------|------------------------------------|
| Erc20Evm / SolErc20Wasm | `erc20evm.time`, `solerc20wasm.time` |
| Erc721 / SolErc721 | `erc721evm.time`, `solerc721wasm.time` |
| Erc1155 | `erc1155evm.time`, `solerc1155wasm.time` |
| Uniswap | `uniswap.time`, `uniswap.wasm.time` |
| Fib | `fibevm_opt.time`, `solfibwasm.time`, `cfibwasm.time` |
| Counter | `counterevm_opt.time`, `solcounterwasm.time` |
