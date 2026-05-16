#!/usr/bin/env python3
# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fetch deployed runtime bytecode for a curated list of high-traffic mainnet
contracts via a public JSON-RPC endpoint, dedupe by codehash, and write hex +
manifest. No archive node is required because deployed runtime bytecode is
immutable after deployment (for contracts that have not SELFDESTRUCT'd).

Output layout (under --out):
  raw/<address>.hex          # runtime bytecode (0x-prefixed hex)
  meta/<address>.meta.json   # per-contract metadata row

Manifest rows: address, name, codehash, code_size, n_jumpdests, n_jumps,
n_jumpis, dyn_jump_ratio.

Usage:
  fetch_topcontracts.py --out tests/corpus/evm-cache \\
    --manifest tests/corpus/evm-cache/manifest_top.json \\
    [--rpc https://ethereum.publicnode.com] [--workers 8] [--min-size 200]
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

# Curated list of high-traffic mainnet contracts: stablecoins, DEX routers,
# pools, lending markets, NFT marketplaces, infrastructure. Selection
# rationale: each row is referenced by name+role so the rationale stays
# auditable. Addresses are mainnet checksum-encoded. Picked to span
# bytecode-size deciles (~400B proxy stubs to ~24KB EIP-170-capped impls).
TOP_CONTRACTS: List[Tuple[str, str]] = [
    # Stablecoins
    ("0xdAC17F958D2ee523a2206206994597C13D831ec7", "USDT"),
    ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USDC"),
    ("0x6B175474E89094C44Da98b954EedeAC495271d0F", "DAI"),
    ("0x4Fabb145d64652a948d72533023f6E7A623C7C53", "BUSD"),
    ("0x853d955aCEf822Db058eb8505911ED77F175b99e", "FRAX"),
    ("0x5f98805A4E8be255a32880FDeC7F6728C6568bA0", "LUSD"),
    ("0x0000000000085d4780B73119b644AE5ecd22b376", "TUSD"),
    # Wrapped/staked assets
    ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "WETH9"),
    ("0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", "stETH"),
    ("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0", "wstETH"),
    ("0xae78736Cd615f374D3085123A210448E74Fc6393", "rETH"),
    ("0xCdF7028ceAB81fA0C6971208e83fa7872994beE5", "TNT"),
    # Uniswap
    ("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "UniswapV2Router02"),
    ("0xE592427A0AEce92De3Edee1F18E0157C05861564", "UniswapV3SwapRouter"),
    ("0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "UniswapV3SwapRouter02"),
    ("0xC36442b4a4522E871399CD717aBDD847Ab11FE88", "UniswapV3NFTManager"),
    ("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", "UniswapV2Factory"),
    ("0x1F98431c8aD98523631AE4a59f267346ea31F984", "UniswapV3Factory"),
    # SushiSwap
    ("0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F", "SushiSwapRouter02"),
    ("0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac", "SushiSwapFactory"),
    # Curve
    ("0xD51a44d3FaE010294C616388b506AcdA1bfAAE46", "Curve3CryptoSwap"),
    ("0xDC24316b9AE028F1497c275EB9192a3Ea0f67022", "CurveStETHPool"),
    ("0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7", "Curve3Pool"),
    # Balancer
    ("0xBA12222222228d8Ba445958a75a0704d566BF2C8", "BalancerVault"),
    # Aave
    ("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "AaveV3Pool"),
    ("0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9", "AaveV2LendingPool"),
    # Compound
    ("0xc3d688B66703497DAA19211EEdff47f25384cdc3", "CompoundV3USDC"),
    ("0x39AA39c021dfbaE8faC545936693aC917d5E7563", "cUSDC"),
    ("0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643", "cDAI"),
    # MakerDAO
    ("0x9759A6Ac90977b93B58547b4A71c78317f391A28", "MakerDaoJoinPSM"),
    ("0x89B78CfA322F6C5dE0aBcEecab66Aee45393cC5A", "MakerDaoPSMUSDC"),
    # Lido
    ("0x442af784A788A5bd6F42A01Ebe9F287a871243fb", "LidoStakingRouter"),
    # ENS
    ("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e", "ENSRegistry"),
    ("0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85", "ENSBaseRegistrar"),
    # OpenSea / NFT
    ("0x00000000006c3852cbEf3e08E8dF289169EdE581", "Seaport1.1"),
    ("0x0000000000000068F116a894984e2DB1123eB395", "Seaport1.6"),
    ("0x00000000001594C61dD8a6804da9AB58eD2483ce", "ConduitController"),
    # CryptoPunks/BAYC
    ("0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB", "CryptoPunksMarket"),
    ("0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D", "BAYC"),
    # Chainlink
    ("0x5147eA642CAEF7BD9c2315996F6A55a8B9b56C76", "ChainlinkETHUSD"),
    ("0xCfE54B5cD566aB89272946F602D76Ea879CAb4a8", "ChainlinkBTCUSD"),
    # Multicall / Permit2
    ("0x000000000022D473030F116dDEE9F6B43aC78BA3", "Permit2"),
    ("0xeefBa1e63905eF1D7ACbA5a8513c70307C1cE441", "Multicall"),
    ("0xcA11bde05977b3631167028862bE2a173976CA11", "Multicall3"),
    # WBTC / RenBTC
    ("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", "WBTC"),
    ("0xEB4C2781e4ebA804CE9a9803C67d0893436bB27D", "renBTC"),
    # 1inch
    ("0x111111125421cA6dc452d289314280a0f8842A65", "1inchAggregationV6"),
    ("0x1111111254EEB25477B68fb85Ed929f73A960582", "1inchAggregationV5"),
    # Yearn
    ("0xa258C4606Ca8206D8aA700cE2143D7db854D168c", "YearnVaultsRegistry"),
    # Convex
    ("0xF403C135812408BFbE8713b5A23a04b3D48AAE31", "ConvexBooster"),
    # Liquity
    ("0x24179CD81c9e782A4096035f7eC97fB8B783e007", "LiquityTroveManager"),
    # GMX
    ("0xA906F338CB21815cBc4Bc87ace9e68c87eF8d8F1", "GMXVault"),
    # Synthetix
    ("0x97607b048aEa97A821C3EdC881aF7743f8868816", "SynthetixV3Core"),
    # 0x Protocol
    ("0xDef1C0ded9bec7F1a1670819833240f027b25EfF", "0xExchangeProxy"),
    # Paraswap
    ("0xDEF171Fe48CF0115B1d80b88dc8eAB59176FEe57", "ParaswapV5"),
    # CoW Protocol
    ("0x9008D19f58AAbD9eD0D60971565AA8510560ab41", "CoWSwapSettlement"),
    # MetaMask Swap Router
    ("0x881D40237659C251811CEC9c364ef91dC08D300C", "MetaMaskSwapRouter"),
    # Aragon
    ("0xa3D55c5C73CcaB37500EBD685569B59B0bE2c8a3", "AragonDAO"),
    # rocketpool
    ("0xae78736Cd615f374D3085123A210448E74Fc6393", "RocketPoolRETH"),
    ("0xDD3f50F8A6CafbE9b31a427582963f465E745AF8", "RocketPoolNodeDeposit"),
    # MEV bots / common
    ("0xa57Bd00134B2850B2a1c55860c9e9ea100fDd6CF", "MEV Bot"),
    # Layer2 bridges / OP Stack
    ("0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1", "OptimismGateway"),
    ("0x8eb8a3b98659cce290402893d0123abb75e3ab28", "AvalancheBridge"),
    ("0xa0c68c638235ee32657e8f720a23cec1bfc77c77", "PolygonRootChainManager"),
    # Lookout for misc popular
    ("0x4d224452801ACEd8B2F0aebE155379bb5D594381", "ApeCoin"),
    ("0x514910771AF9Ca656af840dff83E8264EcF986CA", "LINK"),
    ("0xc944E90C64B2c07662A292be6244BDf05Cda44a7", "GRT"),
    ("0x1985365e9f78359a9B6AD760e32412f4a445E862", "REP"),
    ("0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2", "MKR"),
    ("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", "UNI"),
    ("0x6810e776880C02933D47DB1b9fc05908e5386b96", "GNO"),
    ("0xE41d2489571d322189246DaFA5ebDe1F4699F498", "ZRX"),
    ("0xD533a949740bb3306d119CC777fa900bA034cd52", "CRV"),
    ("0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE", "SHIB"),
    ("0x6f259637dcD74C767781E37Bc6133cd6A68aa161", "HT"),
    ("0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72", "ENS"),
    ("0xa1d65E8fB6e87b60FECCBc582F7f97804B725521", "DXD"),
    ("0x408e41876cCCDC0F92210600ef50372656052a38", "REN"),
    ("0x4575f41308EC1483f3d399aa9a2826d74Da13Deb", "OXT"),
    ("0xc00e94Cb662C3520282E6f5717214004A7f26888", "COMP"),
    ("0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9", "AAVE"),
    ("0x57Ab1ec28D129707052df4dF418D58a2D46d5f51", "sUSD"),
    ("0x0bc529c00C6401aEF6D220BE8C6Ea1667F6Ad93e", "YFI"),
    ("0xba100000625a3754423978a60c9317c58a424e3D", "BAL"),
    ("0x4E15361FD6b4BB609Fa63C81A2be19d873717870", "FTM"),
    ("0x6B3595068778DD592e39A122f4f5a5cF09C90fE2", "SUSHI"),
    ("0x77777FeDdddFfC19Ff86DB637967013e6C6A116C", "Tornado100ETH"),
    ("0xCCCCCcCCCcCccCCCCCCCcCCcCCcCcCccCcCCcCCC", "AnnexProtocol"),
    ("0xfffd8963eFD1fC6A506488495d951d5263988D25", "UniswapV3Factory"),
]


def http_post_rpc(url: str, body: dict, timeout: int = 20) -> Optional[dict]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "dtvm-evm-cache-bench/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as e:
        return {"error": str(e)}


def fetch_code(rpc: str, address: str, retries: int = 3) -> Optional[str]:
    body = {"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [address, "latest"]}
    for attempt in range(retries):
        r = http_post_rpc(rpc, body)
        if r is None:
            time.sleep(0.5)
            continue
        if "result" in r and isinstance(r["result"], str):
            return r["result"]
        time.sleep(0.5 * (attempt + 1))
    return None


def static_jump_stats(code: bytes) -> Tuple[int, int, int, float]:
    OP_JUMP = 0x56
    OP_JUMPI = 0x57
    OP_JUMPDEST = 0x5B
    PUSH1 = 0x60
    PUSH32 = 0x7F
    n_jd = n_jump = n_jumpi = n_dyn = 0
    pc = 0
    prev_was_push = False
    n = len(code)
    while pc < n:
        op = code[pc]
        if op == OP_JUMPDEST:
            n_jd += 1
            prev_was_push = False
            pc += 1
            continue
        if op == OP_JUMP:
            n_jump += 1
            if not prev_was_push:
                n_dyn += 1
            prev_was_push = False
            pc += 1
            continue
        if op == OP_JUMPI:
            n_jumpi += 1
            if not prev_was_push:
                n_dyn += 1
            prev_was_push = False
            pc += 1
            continue
        if PUSH1 <= op <= PUSH32:
            sz = op - PUSH1 + 1
            prev_was_push = True
            pc += 1 + sz
            continue
        prev_was_push = False
        pc += 1
    total = n_jump + n_jumpi
    return n_jd, n_jump, n_jumpi, (n_dyn / total if total else 0.0)


def strip_hex(s: str) -> bytes:
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    return bytes.fromhex(s)


def fetch_one(rpc: str, addr: str, name: str, min_size: int) -> Optional[Tuple[dict, str]]:
    """Fetch + parse; return (row, raw_hex) or None. Caller decides where to
    write so we can dedupe before touching the filesystem."""
    raw = fetch_code(rpc, addr)
    if not raw or raw in ("0x", "0x0"):
        return None
    try:
        code = strip_hex(raw)
    except ValueError:
        return None
    if len(code) < min_size:
        return None
    codehash = hashlib.sha256(code).hexdigest()[:16]
    n_jd, n_jump, n_jumpi, dyn_ratio = static_jump_stats(code)
    row = {
        "address": addr, "name": name, "codehash": codehash,
        "code_size": len(code), "n_jumpdests": n_jd,
        "n_jumps": n_jump, "n_jumpis": n_jumpi, "dyn_jump_ratio": dyn_ratio,
    }
    return (row, raw)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="hex / meta output dir")
    ap.add_argument("--manifest", required=True, help="manifest JSON path")
    ap.add_argument("--rpc", default="https://ethereum.publicnode.com")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--min-size", type=int, default=200,
                    help="skip contracts with runtime bytecode < this many bytes")
    args = ap.parse_args()

    raw_dir = os.path.join(args.out, "raw")
    meta_dir = os.path.join(args.out, "meta")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(meta_dir, exist_ok=True)

    seen: Dict[str, dict] = {}
    raw_payloads: Dict[str, str] = {}
    print(f"fetching {len(TOP_CONTRACTS)} contracts via {args.rpc}", file=sys.stderr)
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        fut_to = {
            ex.submit(fetch_one, args.rpc, addr, name, args.min_size): (addr, name)
            for addr, name in TOP_CONTRACTS
        }
        for fut in cf.as_completed(fut_to):
            addr, name = fut_to[fut]
            result = fut.result()
            if result is None:
                print(f"  miss: {name} ({addr})", file=sys.stderr)
                continue
            row, raw = result
            h = row["codehash"]
            if h in seen:
                print(f"  dup-codehash: {name} == {seen[h]['name']}", file=sys.stderr)
                continue
            seen[h] = row
            raw_payloads[addr] = raw

    for row in seen.values():
        addr = row["address"]
        with open(os.path.join(raw_dir, f"{addr}.hex"), "w") as f:
            f.write(raw_payloads[addr])
        with open(os.path.join(meta_dir, f"{addr}.meta.json"), "w") as f:
            json.dump(row, f, indent=2)

    manifest = list(seen.values())
    with open(args.manifest, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"wrote {len(manifest)} unique contracts to {raw_dir}", file=sys.stderr)


if __name__ == "__main__":
    main()
