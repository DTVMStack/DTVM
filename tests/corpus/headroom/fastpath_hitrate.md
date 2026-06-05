# Per-Opcode Fast-Path Hit-Rate Report

Which lowering path the multipass JIT actually emitted for each compiled arithmetic / compare / bitwise site, aggregated per opcode, over the 225-fixture mainnet replay corpus. The path is read back from the builder after each handler commits to a path; opcodes with no narrow/const fast path record FULL for every site, so their hit rate is honestly 0.

Fast-path hit rate = fraction of sites (or executions) whose path is CONST_U64/NARROW (a runtime fast path). FOLDED is reported separately: both operands constant, computed at compile time, no runtime op. FULL is genuine 256-bit runtime arithmetic. Paths: FOLDED, CONST_U64 (const-specialized), NARROW_U64 (both-fit-u64), NARROW_U128 (u128 fast path), FULL (256-bit).

Two weightings:

- **SITE-weighted**: over distinct (codehash, pc) static sites — one vote per compiled site.
- **EXECUTION-weighted**: each site joined to its exec_count from the runtime site histogram (summed over operand_index), then weighted by executions. Sites with no histogram match are dropped from the execution column (see note below).

Note: 20721 distinct site(s) had no matching exec_count in the histogram and are excluded from the EXECUTION-weighted columns only.

## Fast-path hit rate per opcode

| opcode | sites | site fast-hit % | site folded % | execs | exec fast-hit % | exec folded % |
|---|---:|---:|---:|---:|---:|---:|
| ADD | 8755 | 72.55% | 2.35% | 27818 | 60.32% | 0.74% |
| ISZERO | 2557 | 0.00% | 1.13% | 3031 | 0.00% | 0.00% |
| AND | 2525 | 22.18% | 7.21% | 5738 | 46.60% | 3.17% |
| SUB | 2134 | 14.29% | 26.24% | 3056 | 2.68% | 4.45% |
| SHL | 1548 | 0.00% | 73.32% | 2180 | 0.00% | 7.80% |
| EQ | 1142 | 58.14% | 0.00% | 3602 | 79.40% | 0.00% |
| SHR | 879 | 0.00% | 0.23% | 896 | 0.00% | 0.00% |
| LT | 868 | 24.31% | 0.12% | 4610 | 16.27% | 0.00% |
| GT | 695 | 50.50% | 2.01% | 3938 | 79.18% | 0.00% |
| BYTE | 398 | 93.47% | 0.00% | 154 | 37.66% | 0.00% |
| SLT | 387 | 0.00% | 0.00% | 1248 | 0.00% | 0.00% |
| MUL | 357 | 59.66% | 2.80% | 458 | 41.92% | 7.86% |
| NOT | 340 | 0.00% | 91.18% | 19 | 0.00% | 100.00% |
| OR | 327 | 6.12% | 1.22% | 1812 | 1.32% | 1.10% |
| DIV | 150 | 18.00% | 0.00% | 216 | 21.30% | 0.00% |
| XOR | 60 | 8.33% | 0.00% | 68 | 5.88% | 0.00% |
| SGT | 31 | 0.00% | 0.00% | 692 | 0.00% | 0.00% |
| MOD | 6 | 33.33% | 0.00% | 0 | 0.00% | 0.00% |
| SAR | 4 | 0.00% | 0.00% | 0 | 0.00% | 0.00% |
| SDIV | 2 | 0.00% | 0.00% | 0 | 0.00% | 0.00% |
| MULMOD | 2 | 0.00% | 0.00% | 18 | 0.00% | 0.00% |

## Per-path breakdown (SITE-weighted, % of sites)

| opcode | sites | FOLDED | CONST_U64 | NARROW_U64 | NARROW_U128 | FULL |
|---|---:|---:|---:|---:|---:|---:|
| ADD | 8755 | 206 (2.4%) | 6350 (72.5%) | 0 (0.0%) | 2 (0.0%) | 2197 (25.1%) |
| ISZERO | 2557 | 29 (1.1%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 2528 (98.9%) |
| AND | 2525 | 182 (7.2%) | 376 (14.9%) | 93 (3.7%) | 91 (3.6%) | 1783 (70.6%) |
| SUB | 2134 | 560 (26.2%) | 305 (14.3%) | 0 (0.0%) | 0 (0.0%) | 1269 (59.5%) |
| SHL | 1548 | 1135 (73.3%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 413 (26.7%) |
| EQ | 1142 | 0 (0.0%) | 664 (58.1%) | 0 (0.0%) | 0 (0.0%) | 478 (41.9%) |
| SHR | 879 | 2 (0.2%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 877 (99.8%) |
| LT | 868 | 1 (0.1%) | 211 (24.3%) | 0 (0.0%) | 0 (0.0%) | 656 (75.6%) |
| GT | 695 | 14 (2.0%) | 351 (50.5%) | 0 (0.0%) | 0 (0.0%) | 330 (47.5%) |
| BYTE | 398 | 0 (0.0%) | 372 (93.5%) | 0 (0.0%) | 0 (0.0%) | 26 (6.5%) |
| SLT | 387 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 387 (100.0%) |
| MUL | 357 | 10 (2.8%) | 213 (59.7%) | 0 (0.0%) | 0 (0.0%) | 134 (37.5%) |
| NOT | 340 | 310 (91.2%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 30 (8.8%) |
| OR | 327 | 4 (1.2%) | 20 (6.1%) | 0 (0.0%) | 0 (0.0%) | 303 (92.7%) |
| DIV | 150 | 0 (0.0%) | 27 (18.0%) | 0 (0.0%) | 0 (0.0%) | 123 (82.0%) |
| XOR | 60 | 0 (0.0%) | 5 (8.3%) | 0 (0.0%) | 0 (0.0%) | 55 (91.7%) |
| SGT | 31 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 31 (100.0%) |
| MOD | 6 | 0 (0.0%) | 2 (33.3%) | 0 (0.0%) | 0 (0.0%) | 4 (66.7%) |
| SAR | 4 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 4 (100.0%) |
| SDIV | 2 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 2 (100.0%) |
| MULMOD | 2 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 2 (100.0%) |

## Per-path breakdown (EXECUTION-weighted, % of executions)

| opcode | sites | FOLDED | CONST_U64 | NARROW_U64 | NARROW_U128 | FULL |
|---|---:|---:|---:|---:|---:|---:|
| ADD | 27818 | 206 (0.7%) | 16780 (60.3%) | 0 (0.0%) | 0 (0.0%) | 10832 (38.9%) |
| ISZERO | 3031 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 3031 (100.0%) |
| AND | 5738 | 182 (3.2%) | 1632 (28.4%) | 542 (9.4%) | 500 (8.7%) | 2882 (50.2%) |
| SUB | 3056 | 136 (4.5%) | 82 (2.7%) | 0 (0.0%) | 0 (0.0%) | 2838 (92.9%) |
| SHL | 2180 | 170 (7.8%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 2010 (92.2%) |
| EQ | 3602 | 0 (0.0%) | 2860 (79.4%) | 0 (0.0%) | 0 (0.0%) | 742 (20.6%) |
| SHR | 896 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 896 (100.0%) |
| LT | 4610 | 0 (0.0%) | 750 (16.3%) | 0 (0.0%) | 0 (0.0%) | 3860 (83.7%) |
| GT | 3938 | 0 (0.0%) | 3118 (79.2%) | 0 (0.0%) | 0 (0.0%) | 820 (20.8%) |
| BYTE | 154 | 0 (0.0%) | 58 (37.7%) | 0 (0.0%) | 0 (0.0%) | 96 (62.3%) |
| SLT | 1248 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 1248 (100.0%) |
| MUL | 458 | 36 (7.9%) | 192 (41.9%) | 0 (0.0%) | 0 (0.0%) | 230 (50.2%) |
| NOT | 19 | 19 (100.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| OR | 1812 | 20 (1.1%) | 24 (1.3%) | 0 (0.0%) | 0 (0.0%) | 1768 (97.6%) |
| DIV | 216 | 0 (0.0%) | 46 (21.3%) | 0 (0.0%) | 0 (0.0%) | 170 (78.7%) |
| XOR | 68 | 0 (0.0%) | 4 (5.9%) | 0 (0.0%) | 0 (0.0%) | 64 (94.1%) |
| SGT | 692 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 692 (100.0%) |
| MOD | 0 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| SAR | 0 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| SDIV | 0 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| MULMOD | 18 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 18 (100.0%) |

