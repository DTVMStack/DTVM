# Analysis-Precision Headroom Report

Joins interpreter dynamic limb-width (Stream A) with JIT static value-range (Stream B) on (codehash, pc, opcode).

## Headline

**runtime_narrow_but_static_unknown_ratio = 0.652** (1438.0 of 2205.0 dynamic-u64 slot-mass left unproven over 2330 joined operand slots).

## Join coverage

| metric | value |
|---|---|
| Stream A distinct (codehash,pc,opcode) | 1233 |
| Stream B distinct (codehash,pc,opcode) | 11406 |
| shared keys (joined) | 1165 |

## Headroom by source_kind

| source_kind | slots | dynamic_u64_rate | analyzer_proved_u64_rate | missed_headroom |
|---|---:|---:|---:|---:|
| SLOAD | 9 | 1.000 | 0.000 | 1.000 |
| MLOAD | 178 | 0.996 | 0.000 | 0.996 |
| PRIOR_ARITH | 170 | 0.986 | 0.029 | 0.957 |
| OTHER | 1175 | 0.937 | 0.027 | 0.910 |
| CALLDATALOAD | 27 | 0.741 | 0.000 | 0.741 |
| PUSH | 771 | 0.947 | 0.947 | 0.000 |

## Headroom by opcode

| opcode | slots | dynamic_u64_rate | analyzer_proved_u64_rate | missed_headroom |
|---|---:|---:|---:|---:|
| MULMOD | 2 | 1.000 | 0.000 | 1.000 |
| ADD | 1962 | 0.974 | 0.349 | 0.625 |
| DIV | 28 | 0.643 | 0.036 | 0.607 |
| SUB | 284 | 0.799 | 0.218 | 0.581 |
| MUL | 54 | 0.870 | 0.352 | 0.519 |

## Headroom by app_class

| app_class | slots | dynamic_u64_rate | analyzer_proved_u64_rate | missed_headroom |
|---|---:|---:|---:|---:|
| nft | 1144 | 0.963 | 0.303 | 0.660 |
| unknown | 14 | 0.714 | 0.071 | 0.643 |
| infra | 582 | 0.966 | 0.333 | 0.632 |
| dex | 136 | 0.934 | 0.346 | 0.588 |
| stablecoin | 426 | 0.894 | 0.387 | 0.507 |
| lending | 28 | 0.821 | 0.464 | 0.357 |

