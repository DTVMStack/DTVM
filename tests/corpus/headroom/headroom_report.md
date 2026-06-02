# Analysis-Precision Headroom Report

Joins interpreter dynamic limb-width (Stream A) with JIT static value-range (Stream B) on (codehash, pc, opcode).

## Headline

**runtime_narrow_but_static_unknown_ratio = 0.600** (2460.2 of 4097.2 dynamic-u64 slot-mass left unproven over 4652 joined operand slots).

## Join coverage

| metric | value |
|---|---|
| Stream A distinct (codehash,pc,opcode) | 2597 |
| Stream B distinct (codehash,pc,opcode) | 23167 |
| shared keys (joined) | 2446 |

## Headroom by source_kind

| source_kind | slots | dynamic_u64_rate | analyzer_proved_u64_rate | missed_headroom |
|---|---:|---:|---:|---:|
| SLOAD | 33 | 1.000 | 0.000 | 1.000 |
| CALL_RET | 13 | 1.000 | 0.000 | 1.000 |
| OTHER | 1539 | 0.944 | 0.019 | 0.925 |
| MLOAD | 284 | 0.884 | 0.000 | 0.884 |
| PRIOR_ARITH | 343 | 0.915 | 0.035 | 0.880 |
| SHIFT | 129 | 0.698 | 0.000 | 0.698 |
| CALLDATALOAD | 200 | 0.676 | 0.000 | 0.676 |
| ENV | 135 | 0.659 | 0.000 | 0.659 |
| BITWISE | 47 | 0.489 | 0.000 | 0.489 |
| AND | 126 | 0.705 | 0.381 | 0.324 |
| COMPARE | 258 | 1.000 | 0.767 | 0.233 |
| PUSH | 1539 | 0.877 | 0.877 | 0.000 |
| KECCAK | 6 | 0.000 | 0.000 | 0.000 |

## Headroom by opcode

| opcode | slots | dynamic_u64_rate | analyzer_proved_u64_rate | missed_headroom |
|---|---:|---:|---:|---:|
| SGT | 10 | 1.000 | 0.000 | 1.000 |
| MULMOD | 2 | 1.000 | 0.000 | 1.000 |
| LT | 264 | 0.914 | 0.170 | 0.744 |
| SLT | 90 | 1.000 | 0.333 | 0.667 |
| ADD | 1962 | 0.974 | 0.349 | 0.625 |
| GT | 268 | 0.959 | 0.351 | 0.608 |
| DIV | 28 | 0.643 | 0.036 | 0.607 |
| SUB | 284 | 0.799 | 0.218 | 0.581 |
| MUL | 54 | 0.870 | 0.352 | 0.519 |
| ISZERO | 227 | 0.968 | 0.476 | 0.492 |
| OR | 128 | 0.860 | 0.383 | 0.478 |
| BYTE | 12 | 0.577 | 0.167 | 0.411 |
| XOR | 10 | 0.600 | 0.200 | 0.400 |
| EQ | 506 | 0.869 | 0.486 | 0.383 |
| AND | 500 | 0.504 | 0.206 | 0.298 |
| SHL | 192 | 0.969 | 0.693 | 0.276 |
| SHR | 102 | 0.635 | 0.480 | 0.154 |
| NOT | 13 | 0.692 | 0.692 | 0.000 |

## Headroom by app_class

| app_class | slots | dynamic_u64_rate | analyzer_proved_u64_rate | missed_headroom |
|---|---:|---:|---:|---:|
| nft | 2104 | 0.912 | 0.303 | 0.608 |
| infra | 914 | 0.910 | 0.325 | 0.585 |
| unknown | 53 | 0.868 | 0.340 | 0.528 |
| dex | 469 | 0.855 | 0.433 | 0.422 |
| stablecoin | 982 | 0.831 | 0.444 | 0.387 |
| lending | 130 | 0.646 | 0.346 | 0.300 |

