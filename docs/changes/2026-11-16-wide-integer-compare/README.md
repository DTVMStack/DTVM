# Lower lexicographic two-limb comparisons with CMP/SBB

- Status: Implemented
- Tier: Light
- Date: 2026-11-16

Recognize boolean i32 select trees comparing two i64 limbs. Preserve unsigned
low-limb order and signed/unsigned high-limb order, including <=, >, >= and
inverted equality conditions. Use bounded local snapshot proofs and retain
ordinary lowering whenever identity is not established. See the compiler spec.

This change contains only the comparator. The separate AVX load-folding
experiment, environment switches and native-code dump hooks are excluded.
A deterministic comparison-dense reactor is included in the paper bench
catalog under the explicit `codegen` suite, with WAT source and rebuild steps.
It is a compiler diagnostic, not a contract or a replacement for paper cases.

Final independent 31-round process-wall measurements on the 50M diagnostic:
- Lazy default: 79.927 -> 64.803 ms; paired reduction 19.4% [18.4%,21.7%].
- Lazy FastRA: 96.639 -> 86.630 ms; paired reduction 11.0% [8.2%,13.5%].
- WT45 reference: 58.242 ms. Application gains are not established generally.

See [REPORT.md](REPORT.md) for real regression cases, raw evidence, reproducible
commands, correctness checks and the two unresolved unpinned discovery timeouts.
