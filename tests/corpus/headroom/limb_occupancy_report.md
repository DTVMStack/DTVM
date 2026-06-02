# Limb-Occupancy Distribution Report

Full per-operand limb-occupancy pattern from the interpreter Stream A tap (ZEN_EVM_LIMB_PROFILE) over the 225-fixture mainnet replay corpus. Unlike the magnitude-collapsed `limb_width`, the 4-bit `limb_mask` records which of the four 64-bit limbs (V0 low .. V3 high) are non-zero, so high-sparse values ({0,x,0,0}) are distinguished from dense ones ({x,x,0,0}).

Two weightings are reported side by side:

- **execution-weighted**: every Stream A row is one executed operand (hot loops dominate);
- **distinct-site-weighted**: dedup by (codehash, pc, operand_index), one representative (majority) mask per static site.

| metric | execution-weighted | distinct-site-weighted |
|---|---:|---:|
| operand observations | 61498 | 4931 |

## Grouped occupancy summary

| group | exec count | exec % | site count | site % |
|---|---:|---:|---:|---:|
| ZERO | 6467 | 10.52% | 524 | 10.63% |
| U64 | 50144 | 81.54% | 3814 | 77.35% |
| U128-DENSE | 387 | 0.63% | 42 | 0.85% |
| U192-U256-DENSE | 3894 | 6.33% | 429 | 8.70% |
| HIGH-SPARSE | 425 | 0.69% | 105 | 2.13% |
| MID-GAP | 181 | 0.29% | 17 | 0.34% |

## High-sparse vs dense among non-u64 operands (limb_width>=2)

Of the operands that do NOT fit in a single 64-bit limb, how many are HIGH-SPARSE (low limb zero, a higher limb set) versus DENSE (contiguous from V0)? MID-GAP (V0 set with a zero gap below a set high limb) is listed separately so the rows sum to the non-u64 total.

| split | exec count | exec % of non-u64 | site count | site % of non-u64 |
|---|---:|---:|---:|---:|
| HIGH-SPARSE | 425 | 8.70% | 105 | 17.71% |
| DENSE | 4281 | 87.60% | 471 | 79.43% |
| MID-GAP | 181 | 3.70% | 17 | 2.87% |
| non-u64 total | 4887 | 100.00% | 593 | 100.00% |

## Full 16-mask distribution

| mask | label | exec count | exec % | site count | site % |
|---:|---|---:|---:|---:|---:|
| 0 | 0000 ZERO | 6467 | 10.52% | 524 | 10.63% |
| 1 | 0001 U64 (V0 low only) | 50144 | 81.54% | 3814 | 77.35% |
| 2 | 0010 HIGH-SPARSE single (V1) | 16 | 0.03% | 8 | 0.16% |
| 3 | 0011 U128-dense (V0,V1) | 387 | 0.63% | 42 | 0.85% |
| 4 | 0100 HIGH-SPARSE single (V2) | 139 | 0.23% | 30 | 0.61% |
| 5 | 0101 MID-GAP (V0,V2) | 112 | 0.18% | 6 | 0.12% |
| 6 | 0110 HIGH-SPARSE (V1,V2; low zero) | 1 | 0.00% | 1 | 0.02% |
| 7 | 0111 U192-dense (V0,V1,V2) | 2497 | 4.06% | 323 | 6.55% |
| 8 | 1000 HIGH-SPARSE single (V3) | 224 | 0.36% | 42 | 0.85% |
| 9 | 1001 MID-GAP (V0,V3) | 9 | 0.01% | 3 | 0.06% |
| 10 | 1010 HIGH-SPARSE (V1,V3; low zero) | 0 | 0.00% | 0 | 0.00% |
| 11 | 1011 MID-GAP (V0,V1,V3; gap at V2) | 60 | 0.10% | 8 | 0.16% |
| 12 | 1100 HIGH-SPARSE (V2,V3; low zero) | 6 | 0.01% | 6 | 0.12% |
| 13 | 1101 MID-GAP (V0,V2,V3; gap at V1) | 0 | 0.00% | 0 | 0.00% |
| 14 | 1110 HIGH-SPARSE (V1,V2,V3; low zero) | 39 | 0.06% | 18 | 0.37% |
| 15 | 1111 U256-dense (V0..V3) | 1397 | 2.27% | 106 | 2.15% |

## Per-opcode grouped breakdown (execution-weighted)

Group counts per opcode, execution-weighted. SHL and MUL are the usual producers of high-sparse values; this breakdown shows where each occupancy class concentrates.

| opcode | total | ZERO | U64 | U128-DENSE | U192-U256-DENSE | HIGH-SPARSE | MID-GAP |
|---|---:|---:|---:|---:|---:|---:|---:|
| ADD | 28612 | 1119 (4%) | 26644 (93%) | 0 (0%) | 849 (3%) | 0 (0%) | 0 (0%) |
| AND | 5948 | 650 (11%) | 2820 (47%) | 308 (5%) | 2065 (35%) | 61 (1%) | 44 (1%) |
| LT | 4908 | 666 (14%) | 4142 (84%) | 4 (0%) | 87 (2%) | 9 (0%) | 0 (0%) |
| GT | 4048 | 500 (12%) | 3479 (86%) | 43 (1%) | 26 (1%) | 0 (0%) | 0 (0%) |
| EQ | 3620 | 376 (10%) | 2920 (81%) | 2 (0%) | 309 (9%) | 8 (0%) | 5 (0%) |
| ISZERO | 3158 | 977 (31%) | 2092 (66%) | 2 (0%) | 86 (3%) | 1 (0%) | 0 (0%) |
| SUB | 3130 | 250 (8%) | 2481 (79%) | 3 (0%) | 304 (10%) | 92 (3%) | 0 (0%) |
| SHL | 2290 | 288 (13%) | 1996 (87%) | 0 (0%) | 6 (0%) | 0 (0%) | 0 (0%) |
| OR | 1868 | 1235 (66%) | 506 (27%) | 15 (1%) | 60 (3%) | 40 (2%) | 12 (1%) |
| SLT | 1290 | 43 (3%) | 1247 (97%) | 0 (0%) | 0 (0%) | 0 (0%) | 0 (0%) |
| SHR | 902 | 153 (17%) | 486 (54%) | 0 (0%) | 50 (6%) | 115 (13%) | 98 (11%) |
| SGT | 692 | 0 (0%) | 692 (100%) | 0 (0%) | 0 (0%) | 0 (0%) | 0 (0%) |
| MUL | 466 | 47 (10%) | 388 (83%) | 2 (0%) | 29 (6%) | 0 (0%) | 0 (0%) |
| DIV | 216 | 73 (34%) | 66 (31%) | 5 (2%) | 0 (0%) | 50 (23%) | 22 (10%) |
| BYTE | 154 | 74 (48%) | 29 (19%) | 0 (0%) | 2 (1%) | 49 (32%) | 0 (0%) |
| EXP | 86 | 15 (17%) | 71 (83%) | 0 (0%) | 0 (0%) | 0 (0%) | 0 (0%) |
| XOR | 68 | 1 (1%) | 47 (69%) | 0 (0%) | 20 (29%) | 0 (0%) | 0 (0%) |
| NOT | 24 | 0 (0%) | 20 (83%) | 3 (12%) | 1 (4%) | 0 (0%) | 0 (0%) |
| MULMOD | 18 | 0 (0%) | 18 (100%) | 0 (0%) | 0 (0%) | 0 (0%) | 0 (0%) |

