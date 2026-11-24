# Lower variable integer shifts with BMI2

- **Status**: Proposed
- **Date**: 2026-11-24
- **Tier**: Light

Use the x86 subtarget's BMI2 feature for 32- and 64-bit register-count left,
arithmetic right, and logical right shifts when Multipass selects FastRA.
Both instruction forms mask the count to the operand width. Immediate shifts,
rotations, GreedyRA, and CPUs without BMI2 use the existing lowering paths.

- [ ] Check the value, count masking, and preservation of live operands.
- [ ] Disassemble the hot loop and validate the non-BMI2 path.
- [ ] Compare main, candidate, and Wasmtime 45 on shift kernels and catalog cases.
