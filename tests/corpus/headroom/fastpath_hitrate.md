# Per-Opcode Fast-Path Hit-Rate Report

Which lowering path the multipass JIT actually emitted for each compiled arithmetic / compare / bitwise site, aggregated per opcode, over the 225-fixture mainnet replay corpus. The path is read back from the builder after each handler commits to a path; opcodes with no narrow/const fast path record FULL for every site, so their hit rate is honestly 0.

Fast-path hit rate = fraction of sites (or executions) whose path is CONST_U64/NARROW (a runtime fast path). FOLDED is reported separately: both operands constant, computed at compile time, no runtime op. FULL is genuine 256-bit runtime arithmetic. Paths: FOLDED, CONST_U64 (const-specialized), NARROW_U64 (both-fit-u64), NARROW_U128 (u128 fast path), FULL (256-bit).

Two weightings:

- **SITE-weighted**: over distinct (codehash, pc) static sites — one vote per compiled site.
- **EXECUTION-weighted**: each site joined to its exec_count from the runtime site histogram (summed over operand_index), then weighted by executions. Sites with no histogram match are dropped from the execution column (see note below).

Note: 26984 Stream B data row(s) had an unexpected field count (torn final line guard) and were dropped.

Note: 0 distinct site(s) had no matching exec_count in the histogram and are excluded from the EXECUTION-weighted columns only.

## Fast-path hit rate per opcode

| opcode | sites | site fast-hit % | site folded % | execs | exec fast-hit % | exec folded % |
|---|---:|---:|---:|---:|---:|---:|

## Per-path breakdown (SITE-weighted, % of sites)

| opcode | sites | FOLDED | CONST_U64 | NARROW_U64 | NARROW_U128 | FULL |
|---|---:|---:|---:|---:|---:|---:|

## Per-path breakdown (EXECUTION-weighted, % of executions)

| opcode | sites | FOLDED | CONST_U64 | NARROW_U64 | NARROW_U128 | FULL |
|---|---:|---:|---:|---:|---:|---:|

