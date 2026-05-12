# 27-Bench Compare: branch vs combined baseline (40 reps + 20 reps, multipass)
## Per-bench (sign: positive = branch faster). Baseline = mean(run1, ping-pong) per iteration.

| Bench | CombinedBase | Branch | Delta% | 95% CI | Verdict |
|---|---|---|---|---|---|
| main/blake2b_huff/8415nulls | 673.951us | 665.262us | +1.31% | [+0.24, +2.54]% | WEAK-POS |
| main/blake2b_huff/empty | 10.738us | 10.508us | +2.19% | [+1.10, +3.32]% | WEAK-POS |
| main/blake2b_shifts/8415nulls | 3.051ms | 2.980ms | +2.39% | [+0.85, +3.95]% | WEAK-POS |
| main/sha1_divs/5311 | 347.483us | 344.616us | +0.83% | [+0.21, +1.47]% | WEAK-POS |
| main/sha1_divs/empty | 4.823us | 4.796us | +0.56% | [-0.06, +1.24]% | NULL |
| main/sha1_shifts/5311 | 323.340us | 317.616us | +1.80% | [+0.98, +2.77]% | WEAK-POS |
| main/sha1_shifts/empty | 4.641us | 4.539us | +2.24% | [+0.88, +3.82]% | WEAK-POS |
| main/snailtracer/benchmark | 24.380ms | 24.011ms | +1.54% | [+0.76, +2.40]% | WEAK-POS |
| main/structarray_alloc/nfts_rank | 202.212us | 199.889us | +1.16% | [+0.93, +1.40]% | WEAK-POS |
| main/swap_math/insufficient_liquidity | 1.185us | 1.163us | +1.90% | [+1.45, +2.34]% | WEAK-POS |
| main/swap_math/received | 1.756us | 1.735us | +1.23% | [+0.99, +1.47]% | WEAK-POS |
| main/swap_math/spent | 1.481us | 1.471us | +0.68% | [+0.36, +1.00]% | WEAK-POS |
| main/weierstrudel/1 | 168.618us | 167.791us | +0.49% | [-0.26, +1.15]% | NULL |
| main/weierstrudel/15 | 1.881ms | 1.842ms | +2.12% | [+1.22, +3.12]% | WEAK-POS |
| micro/JUMPDEST_n0/empty | 812.4ns | 807.3ns | +0.63% | [+0.37, +0.89]% | WEAK-POS |
| micro/jump_around/empty | 10.839us | 10.740us | +0.92% | [+0.28, +1.69]% | WEAK-POS |
| micro/loop_with_many_jumpdests/empty | 1.798us | 1.788us | +0.58% | [+0.23, +0.89]% | WEAK-POS |
| micro/memory_grow_mload/by1 | 7.618us | 7.557us | +0.80% | [+0.29, +1.30]% | WEAK-POS |
| micro/memory_grow_mload/by16 | 8.257us | 8.268us | -0.13% | [-0.79, +0.51]% | NULL |
| micro/memory_grow_mload/by32 | 9.206us | 9.181us | +0.27% | [-1.18, +1.72]% | NULL |
| micro/memory_grow_mload/nogrow | 7.568us | 7.509us | +0.78% | [+0.27, +1.31]% | WEAK-POS |
| micro/memory_grow_mstore/by1 | 9.591us | 9.408us | +1.95% | [+1.14, +2.82]% | WEAK-POS |
| micro/memory_grow_mstore/by16 | 10.250us | 10.091us | +1.57% | [+1.07, +2.04]% | WEAK-POS |
| micro/memory_grow_mstore/by32 | 11.348us | 11.027us | +2.91% | [+1.77, +4.01]% | WEAK-POS |
| micro/memory_grow_mstore/nogrow | 9.313us | 9.180us | +1.45% | [+0.98, +1.91]% | WEAK-POS |
| micro/signextend/one | 68.569us | 67.969us | +0.88% | [-0.16, +1.93]% | NULL |
| micro/signextend/zero | 68.676us | 67.188us | +2.21% | [+1.50, +2.95]% | WEAK-POS |

**Geomean** | -- | -- | **+1.304%** | [+1.147, +1.465]% | WEAK-POS

## Drift check (ping-pong baseline2 vs baseline1)
Drift geomean = -2.094%
Top-3 negative drift (ping-pong faster):
  micro/memory_grow_mstore/by32: -5.41%
  main/blake2b_shifts/8415nulls: -5.33%
  main/blake2b_huff/empty: -5.30%
Top-3 positive drift (ping-pong slower):
  micro/memory_grow_mload/by1: -0.36%
  main/weierstrudel/1: +0.20%
  micro/memory_grow_mload/by32: +1.09%

Max abs per-bench drift: 5.41%
