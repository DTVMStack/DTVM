# Per-Opcode Fast-Path Hit-Rate Report

Which lowering path the multipass JIT actually emitted for each compiled arithmetic / compare / bitwise site, aggregated per opcode, over the 225-fixture mainnet replay corpus. The path is read back from the builder after each handler commits to a path; opcodes with no narrow/const fast path record FULL for every site, so their hit rate is honestly 0.

Fast-path hit rate = fraction of sites (or executions) whose path is not FULL. Paths: CONST_U64 (const-specialized), NARROW_U64 (both-fit-u64), NARROW_U128 (u128 fast path), FULL (256-bit).

Two weightings:

- **SITE-weighted**: over distinct (codehash, pc) static sites — one vote per compiled site.
- **EXECUTION-weighted**: each site joined to its exec_count from the runtime site histogram (summed over operand_index), then weighted by executions. Sites with no histogram match are dropped from the execution column (see note below).

Note: 20721 distinct site(s) had no matching exec_count in the histogram and are excluded from the EXECUTION-weighted columns only.

## Fast-path hit rate per opcode

| opcode | sites | site fast-hit % | execs | exec fast-hit % |
|---|---:|---:|---:|---:|
| ADD | 8755 | 72.55% | 27818 | 60.32% |
| ISZERO | 2557 | 0.00% | 3031 | 0.00% |
| AND | 2525 | 22.18% | 5738 | 46.60% |
| SUB | 2134 | 14.29% | 3056 | 2.68% |
| SHL | 1548 | 0.00% | 2180 | 0.00% |
| EQ | 1142 | 58.14% | 3602 | 79.40% |
| SHR | 879 | 0.00% | 896 | 0.00% |
| LT | 868 | 24.31% | 4610 | 16.27% |
| GT | 695 | 50.50% | 3938 | 79.18% |
| BYTE | 398 | 93.47% | 154 | 37.66% |
| SLT | 387 | 0.00% | 1248 | 0.00% |
| MUL | 357 | 59.66% | 458 | 41.92% |
| NOT | 340 | 0.00% | 19 | 0.00% |
| OR | 327 | 6.12% | 1812 | 1.32% |
| DIV | 150 | 18.00% | 216 | 21.30% |
| XOR | 60 | 8.33% | 68 | 5.88% |
| SGT | 31 | 0.00% | 692 | 0.00% |
| MOD | 6 | 33.33% | 0 | 0.00% |
| SAR | 4 | 0.00% | 0 | 0.00% |
| SDIV | 2 | 0.00% | 0 | 0.00% |
| MULMOD | 2 | 0.00% | 18 | 0.00% |

## Per-path breakdown (SITE-weighted, % of sites)

| opcode | sites | CONST_U64 | NARROW_U64 | NARROW_U128 | FULL |
|---|---:|---:|---:|---:|---:|
| ADD | 8755 | 6350 (72.5%) | 0 (0.0%) | 2 (0.0%) | 2403 (27.4%) |
| ISZERO | 2557 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 2557 (100.0%) |
| AND | 2525 | 376 (14.9%) | 93 (3.7%) | 91 (3.6%) | 1965 (77.8%) |
| SUB | 2134 | 305 (14.3%) | 0 (0.0%) | 0 (0.0%) | 1829 (85.7%) |
| SHL | 1548 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 1548 (100.0%) |
| EQ | 1142 | 664 (58.1%) | 0 (0.0%) | 0 (0.0%) | 478 (41.9%) |
| SHR | 879 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 879 (100.0%) |
| LT | 868 | 211 (24.3%) | 0 (0.0%) | 0 (0.0%) | 657 (75.7%) |
| GT | 695 | 351 (50.5%) | 0 (0.0%) | 0 (0.0%) | 344 (49.5%) |
| BYTE | 398 | 372 (93.5%) | 0 (0.0%) | 0 (0.0%) | 26 (6.5%) |
| SLT | 387 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 387 (100.0%) |
| MUL | 357 | 213 (59.7%) | 0 (0.0%) | 0 (0.0%) | 144 (40.3%) |
| NOT | 340 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 340 (100.0%) |
| OR | 327 | 20 (6.1%) | 0 (0.0%) | 0 (0.0%) | 307 (93.9%) |
| DIV | 150 | 27 (18.0%) | 0 (0.0%) | 0 (0.0%) | 123 (82.0%) |
| XOR | 60 | 5 (8.3%) | 0 (0.0%) | 0 (0.0%) | 55 (91.7%) |
| SGT | 31 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 31 (100.0%) |
| MOD | 6 | 2 (33.3%) | 0 (0.0%) | 0 (0.0%) | 4 (66.7%) |
| SAR | 4 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 4 (100.0%) |
| SDIV | 2 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 2 (100.0%) |
| MULMOD | 2 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 2 (100.0%) |

## Per-path breakdown (EXECUTION-weighted, % of executions)

| opcode | sites | CONST_U64 | NARROW_U64 | NARROW_U128 | FULL |
|---|---:|---:|---:|---:|---:|
| ADD | 27818 | 16780 (60.3%) | 0 (0.0%) | 0 (0.0%) | 11038 (39.7%) |
| ISZERO | 3031 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 3031 (100.0%) |
| AND | 5738 | 1632 (28.4%) | 542 (9.4%) | 500 (8.7%) | 3064 (53.4%) |
| SUB | 3056 | 82 (2.7%) | 0 (0.0%) | 0 (0.0%) | 2974 (97.3%) |
| SHL | 2180 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 2180 (100.0%) |
| EQ | 3602 | 2860 (79.4%) | 0 (0.0%) | 0 (0.0%) | 742 (20.6%) |
| SHR | 896 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 896 (100.0%) |
| LT | 4610 | 750 (16.3%) | 0 (0.0%) | 0 (0.0%) | 3860 (83.7%) |
| GT | 3938 | 3118 (79.2%) | 0 (0.0%) | 0 (0.0%) | 820 (20.8%) |
| BYTE | 154 | 58 (37.7%) | 0 (0.0%) | 0 (0.0%) | 96 (62.3%) |
| SLT | 1248 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 1248 (100.0%) |
| MUL | 458 | 192 (41.9%) | 0 (0.0%) | 0 (0.0%) | 266 (58.1%) |
| NOT | 19 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 19 (100.0%) |
| OR | 1812 | 24 (1.3%) | 0 (0.0%) | 0 (0.0%) | 1788 (98.7%) |
| DIV | 216 | 46 (21.3%) | 0 (0.0%) | 0 (0.0%) | 170 (78.7%) |
| XOR | 68 | 4 (5.9%) | 0 (0.0%) | 0 (0.0%) | 64 (94.1%) |
| SGT | 692 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 692 (100.0%) |
| MOD | 0 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| SAR | 0 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| SDIV | 0 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| MULMOD | 18 | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 18 (100.0%) |

