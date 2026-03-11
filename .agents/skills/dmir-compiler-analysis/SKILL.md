---
name: dmir-compiler-analysis
description: Analyze DTVM's dMIR intermediate representation and compilation pipeline. Translates EVM bytecode sequences into dMIR pseudocode, then into x86 pseudocode, and evaluates performance cost at each stage. Use when the user asks about dMIR instructions, EVM-to-dMIR conversion, dMIR-to-x86 lowering, JIT compilation cost analysis, EVM opcode performance evaluation, or EVM->dMIR performance optimization.
---

# dMIR Compiler Analysis

## Source Code is Authoritative

This skill provides pseudocode summaries and cost estimates as quick references.
**When analyzing specific optimization opportunities, always read the actual source
code** to verify current behavior. The reference files include exact file paths and
function names for every EVM opcode handler. The code may have evolved since this
skill was written; treat discrepancies as the code being correct.

For each EVM opcode, the complete source trace is:
1. **Dispatch**: `EVMByteCodeVisitor::decode()` in `src/action/evm_bytecode_visitor.h` (line ~108)
2. **Builder**: `EVMMirBuilder::handle*()` in `src/compiler/evm_frontend/evm_mir_compiler.h` (templates) and `evm_mir_compiler.cpp` (implementations)
3. **x86 lowering**: `X86CgLowering::lower*()` in `src/compiler/target/x86/x86lowering.cpp`

See [evm-to-dmir.md](evm-to-dmir.md) for the full per-opcode source location table.

## Compilation Pipeline

```
EVM bytecode
  |  EVMByteCodeVisitor (src/action/evm_bytecode_visitor.h)
  v
EVMMirBuilder (src/compiler/evm_frontend/evm_mir_compiler.h/cpp)
  |  Each EVM opcode -> handler function -> dMIR instructions
  v
dMIR (deterministic MIR)
  |  X86CgLowering (src/compiler/target/x86/x86lowering.cpp)
  v
CGIR (virtual registers)
  |  Register Allocator (FastRA or CgRAGreedy)
  v
CGIR (physical registers)
  |  X86MCLowering -> X86MCInstLower
  v
x86 machine code
```

## U256 Decomposition (Critical)

EVM operates on 256-bit integers. In dMIR, every U256 is decomposed into **4 x i64 limbs** in little-endian order:

```
U256 = [limb0:i64(lo), limb1:i64(mid-lo), limb2:i64(mid-hi), limb3:i64(hi)]
```

Every EVM arithmetic/logic operation on U256 expands to multiple dMIR instructions operating on these 4 limbs. This is the primary source of instruction expansion.

## dMIR Design (from `docs/compiler/dmir.md`)

Key design aspects relevant to optimization work:

- **Inspired by Maple IR** (structure) and **LLVM** (data structures)
- **Not SSA**: Variables allow multiple assignments (simplifies frontend construction)
- **Instruction categories**: **Statements** (linked in BasicBlock, e.g. `dassign`, `store`, `br`) vs **Expressions** (produce values, used as operands, e.g. `add`, `cmp`, `load`)
- **Instruction memory layout**: `[Operands Instruction*..., Instruction's own members]` -- operands are encapsulated as Instructions (unlike LLVM's Value)
- **Module > Function > BasicBlock > Instruction** hierarchy
- **Type system**: `i32`, `i64`, `f32`, `f64`, `FunctionType`, `PointerType`

For full documentation, read `docs/compiler/dmir.md`. For WASM-to-dMIR mapping, read `docs/compiler/wasm_dmir.md`.

## dMIR Instruction Set

Defined in `src/compiler/mir/opcodes.def`:

- **Unary**: `clz`, `ctz`, `not`, `popcnt`, `bswap`, `fpabs`, `fpneg`, `fpsqrt`, `fpround_ceil/floor/trunc/nearest`
- **Binary**: `add`, `sub`, `mul`, `sdiv`, `udiv`, `srem`, `urem`, `and`, `or`, `xor`, `shl`, `sshr`, `ushr`, `rotl`, `rotr`, `fpdiv`, `fpmin`, `fpmax`, `fpcopysign`
- **Overflow**: `wasm_sadd_overflow`, `wasm_uadd_overflow`, `wasm_ssub_overflow`, `wasm_usub_overflow`, `wasm_smul_overflow`, `wasm_umul_overflow`
- **Conversion**: `inttoptr`, `ptrtoint`, `trunc`, `sext`, `uext`, `fptrunc`, `fpext`, `sitofp`, `uitofp`, `bitcast`, `wasm_fptosi`, `wasm_fptoui`
- **Other exprs**: `dread`, `const`, `cmp`, `adc`, `select`, `load`
- **EVM-specific**: `evm_umul128_lo` (64x64->64 low), `evm_umul128_hi` (extract high 64 from umul128)
- **Control flow**: `br`, `br_if`, `switch`, `call`, `icall`, `return`
- **Statements**: `dassign`, `store`, `wasm_check_memory_access`, `wasm_visit_stack_guard`, `wasm_check_stack_boundary`

Condition codes (`src/compiler/mir/cond_codes.def`): `ieq`, `ine`, `iugt`, `iuge`, `iult`, `iule`, `isgt`, `isge`, `islt`, `isle` (integer); `foeq`, `fogt`, `foge`, `folt`, `fole`, `fone`, `ford`, `funo`, `fueq`, `fugt`, `fuge`, `fult`, `fule`, `fune` (float).

## dMIR Textual Format

```
func %<index> (<param_types>) -> <ret_type> {
    var $<idx> <type>
@<bb_label>:
    $<dst> = <opcode> ($<src1>, $<src2>)
    return $<dst>
}
```

Example (i32 add):
```
func %0 (i32, i32) -> i32 {
    var $2 i32
@0:
    $2 = add ($0, $1)
    return $2
}
```

## Translation Workflow

When given EVM bytecode or instruction sequence:

### Step 1: EVM -> dMIR

For each EVM opcode, apply the expansion rules:

1. Identify the opcode category (arithmetic, bitwise, shift, compare, stack, memory, env, control)
2. Decompose U256 operands into 4 limbs
3. Apply the per-limb dMIR pattern from [evm-to-dmir.md](evm-to-dmir.md)
4. Track the EVM stack as `Operand` objects (each holding 4 limb references)

### Step 2: dMIR -> x86 Pseudocode

For each dMIR instruction, apply the x86 lowering from [dmir-to-x86.md](dmir-to-x86.md):

1. Map each dMIR opcode to its x86 instruction pattern
2. Note register constraints (e.g., div/rem require RAX:RDX, shifts require CL)
3. Account for vreg-to-physical-register allocation overhead

### Step 3: Performance Cost Comparison

Use the cost model from [cost-model.md](cost-model.md):

1. For each dMIR instruction, look up its x86 cost (instruction count + latency)
2. Sum total x86 cost for both baseline and proposed implementations
3. Assess qualitative factors: register pressure, dependency chain length, CF chain integrity, select chain depth
4. Compare: `improvement = (old_x86_cost - new_x86_cost) / old_x86_cost`

## Quick Reference: EVM -> dMIR -> x86

| EVM Opcode | dMIR Pattern (per-limb) | dMIR Count | x86 Approx |
|---|---|---|---|
| ADD | `add` + 3x `adc` | ~12 | ~12 (add/adc are 1:1) |
| SUB | 4x `sub` + borrow via `cmp`+`or` | ~20 | ~24 |
| MUL | 10x `evm_umul128_lo/hi` + `add/adc` chains | ~80 | ~100 |
| AND/OR/XOR | 4x `and`/`or`/`xor` | ~8 | ~8 |
| NOT | 4x `xor` with all-ones | ~8 | ~8 |
| SHL | `urem/udiv` decompose + 4x `shl/ushr/or` + `select` chains | ~15 | ~40 |
| SHR | Similar to SHL with `ushr` | ~15 | ~40 |
| SAR | Similar with sign extension | ~15 | ~40 |
| LT/GT | High-to-low `cmp` + `select` chain | ~12 | ~20 |
| SLT/SGT | Same with signed top limb | ~12 | ~20 |
| EQ | 4x `cmp(ieq)` + 3x `and` | ~12 | ~14 |
| ISZERO | 3x `or` + `cmp(ieq,0)` | ~8 | ~10 |
| PUSH0-32 | 4x `const i64` | ~4 | ~4 |
| DUP1-16 | Stack load/store | ~4 | ~4 |
| SWAP1-16 | Stack load/store | ~4 | ~4 |
| MLOAD | Runtime call + bswap | ~8 | ~10 |
| MSTORE | Runtime call + bswap | ~8 | ~10 |
| SLOAD/SSTORE | Runtime call | ~5 | ~8 |
| DIV/SDIV/MOD/SMOD | Runtime call | ~5 | ~8 |
| ADDMOD/MULMOD | Runtime call | ~5 | ~8 |
| EXP | Inline binary exponentiation loop (MUL-heavy) | ~200+ | ~300+ |
| SIGNEXTEND | ~21 `select` chains | ~20 | ~50 |
| BYTE | `select` + shift chain | ~8 | ~20 |
| JUMP | Jump table lookup + `switch` | ~5 | ~8 |
| JUMPI | Compare + conditional `br_if` | ~5 | ~8 |
| ADDRESS/CALLER/... | Runtime call -> U256 result | ~5 | ~8 |
| CALL/STATICCALL/... | Runtime call (complex) | ~5 | ~15 |
| CREATE/CREATE2 | Runtime call | ~5 | ~15 |
| RETURN/REVERT | Runtime call + return | ~5 | ~8 |
| LOG0-LOG4 | Runtime call | ~8 | ~12 |
| KECCAK256 | Runtime call | ~5 | ~8 |

## Key Source Files

Read these when deeper analysis is needed:

| Purpose | File |
|---|---|
| dMIR opcode definitions | `src/compiler/mir/opcodes.def` |
| Condition codes | `src/compiler/mir/cond_codes.def` |
| MIR instructions | `src/compiler/mir/instructions.h` |
| MIR variables | `src/compiler/mir/variable.h` |
| EVM -> dMIR builder | `src/compiler/evm_frontend/evm_mir_compiler.h` |
| EVM -> dMIR handlers | `src/compiler/evm_frontend/evm_mir_compiler.cpp` |
| EVM bytecode dispatch | `src/action/evm_bytecode_visitor.h` |
| EVM analyzer (weights) | `src/compiler/evm_frontend/evm_analyzer.h` |
| dMIR -> CGIR lowering | `src/compiler/cgir/lowering.h` |
| x86 lowering | `src/compiler/target/x86/x86lowering.cpp` |
| x86 MC emission | `src/compiler/target/x86/x86_mc_lowering.h` |
| Virtual reg map | `src/compiler/cgir/pass/virt_reg_map.h` |
| Compiler pipeline | `src/compiler/compiler.cpp` |
| dMIR docs | `docs/compiler/dmir.md` |
| WASM->dMIR mapping | `docs/compiler/wasm_dmir.md` |

## Performance Optimization Workflow

When exploring EVM->dMIR optimization ideas, follow this workflow:

### 1. Baseline Analysis

For the target EVM opcode or sequence:
1. Look up the handler function in the source trace table ([evm-to-dmir.md](evm-to-dmir.md) Section 0)
2. Read the actual handler code to understand the current dMIR expansion
3. Count dMIR instructions and categorize them (compute, control, memory)
4. Apply x86 expansion factors from [dmir-to-x86.md](dmir-to-x86.md) to estimate native cost

### 2. Proposed Optimization

Describe the proposed change to the dMIR expansion:
1. Write the new dMIR pseudocode for the optimized handler
2. Count the new dMIR instruction total
3. Apply x86 expansion factors to estimate new native cost
4. Compute delta: `improvement = (old_x86 - new_x86) / old_x86`

### 3. Feasibility Check

Verify the optimization is valid:
- Does it preserve U256 semantics? (all 256 bits, overflow/underflow behavior)
- Does it maintain the carry chain invariant for ADD? (ADD must immediately precede ADC)
- Does it handle edge cases? (shift >= 256, division by zero, signed overflow)
- Does it affect register pressure? (fewer select chains = less RA stress)
- Is it compatible with gas metering insertion points?

### 4. Impact Assessment

Evaluate overall impact:
- Check `MIR_OPCODE_WEIGHT` in [cost-model.md](cost-model.md) for frequency estimates
- Consider whether the opcode is RA-expensive (affects JIT suitability thresholds)
- Estimate impact on typical EVM bytecode (e.g., ERC-20 transfer, Uniswap swap)

## Additional Resources

- For detailed EVM-to-dMIR pseudocode per opcode with **exact source locations**, see [evm-to-dmir.md](evm-to-dmir.md)
- For dMIR-to-x86 lowering patterns with **exact lowering functions**, see [dmir-to-x86.md](dmir-to-x86.md)
- For the dMIR instruction x86 cost table and implementation comparison methodology, see [cost-model.md](cost-model.md)
