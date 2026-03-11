# dMIR Cost Model for Implementation Comparison

This document provides the cost model for **comparing different EVM->dMIR
implementation approaches**. The core idea: given two dMIR instruction sequences
that implement the same EVM opcode, estimate which one produces faster x86 code.

## How to Compare Two Implementations

```
EVM opcode (e.g. ADD)
  |
  +--[Current handler]--> dMIR sequence A --> count & categorize --> x86 cost A
  |
  +--[Proposed handler]--> dMIR sequence B --> count & categorize --> x86 cost B
  |
  improvement = (x86_cost_A - x86_cost_B) / x86_cost_A
```

### Step 1: Write Out Both dMIR Sequences

Read the current handler source code (see source trace in [evm-to-dmir.md](evm-to-dmir.md)
Section 0) and write out the dMIR instructions it generates. Then write out the
proposed alternative.

### Step 2: Categorize Each dMIR Instruction

For each sequence, count how many dMIR instructions fall into each category
from the cost table below.

### Step 3: Compute x86 Cost

Multiply each count by the x86 expansion factor and sum. Also assess the
qualitative factors (register pressure, dependency chains, etc.).

### Step 4: Compare

The implementation with the lower total x86 cost + better qualitative profile wins.

---

## dMIR Instruction x86 Cost Table

This is the **invariant** part of the cost model. It does not change when you
modify the EVM->dMIR frontend -- it reflects how the x86 backend
(`X86CgLowering` in `src/compiler/target/x86/x86lowering.cpp`) lowers each
dMIR instruction.

| dMIR Instruction | x86 Count | x86 Latency (cycles) | Notes |
|---|---|---|---|
| add | 1 | 1 | ADD64rr |
| sub | 1 | 1 | SUB64rr |
| mul | 1 | 3-4 | IMUL64rr |
| and / or / xor | 1 | 1 | AND/OR/XOR64rr |
| adc | 2 | 1 | COPY + ADC64rr; consumes CF from prior add/adc |
| sdiv / udiv / srem / urem | 4-5 | 20-90 | MOV RAX + CDQ/CQO + IDIV/DIV + MOV result |
| shl / sshr / ushr (immediate) | 1 | 1 | SHL/SAR/SHR64ri |
| shl / sshr / ushr (variable) | 3 | 2 | COPY to CL + KILL + SHL/SAR/SHR64rCL |
| rotl / rotr | 1-3 | 1-2 | ROL/ROR (immediate or via CL) |
| cmp | 2 | 1 | CMP64rr + SETcc |
| select | 2-3 | 1-2 | TEST + CMOVcc (may fuse with preceding cmp) |
| evm_umul128_lo | 4 | 3-4 | COPY RAX + MUL64r + 2x COPY (lo to vreg, hi to vreg) |
| evm_umul128_hi | 0-1 | 0 | Reuses RDX from preceding MUL64r |
| load | 1 | 4-5 (L1 hit) | MOV64rm; cache-miss dominated in practice |
| store | 1 | 4-5 (L1 hit) | MOV64mr |
| bswap | 1 | 1 | BSWAP64r |
| const (integer) | 1 | 1 | MOV64ri or XOR+MOV for small values |
| dread | 0-1 | 0 | COPY vreg (often coalesced away by RA) |
| dassign | 0-1 | 0 | COPY vreg (often coalesced away by RA) |
| call | N+2 | varies | N arg register moves + CALL + result COPY; flushes caller-saved regs |
| icall | N+3 | varies | Same as call but indirect (CALL *reg) |
| br | 1 | 0-1 | JMP (often predicted) |
| br_if | 2 | 0-1 | TEST + Jcc (branch prediction dependent) |
| switch | 2*N | varies | CMP+JE per case, or jump table |
| trunc | 0-1 | 0 | Subreg extract (often free on x86-64) |
| sext | 1 | 1 | MOVSX64rr32 |
| uext | 1 | 0-1 | MOVZX or implicit zero-extend |
| not | 1 | 1 | XOR with all-ones |
| clz / ctz | 2-3 | 3 | BSR+XOR or LZCNT / BSF or TZCNT |
| popcnt | 1 | 3 | POPCNT |

---

## Qualitative Cost Factors

Beyond instruction count, these factors significantly affect real performance:

### 1. Register Pressure

x86-64 has ~14 usable GPRs (16 minus RSP, RBP). If a dMIR sequence has more
simultaneously live virtual registers than physical registers, the RA must
**spill** to the stack, adding load/store pairs (~2 extra x86 instructions + memory
latency per spill).

**How to estimate**: Count the maximum number of dMIR values alive at any point.
For EVM U256 operations, each U256 occupies 4 vregs, so a single binary operation
on two U256 inputs requires ~8 input vregs + 4 output vregs = 12 live vregs at peak.

**Optimization signal**: An implementation that reuses vregs or reduces simultaneous
live values will have fewer spills.

### 2. Dependency Chain Length

x86 CPUs execute instructions out-of-order but are limited by data dependencies.
A long chain of dependent instructions (e.g. `add -> adc -> adc -> adc`) executes
sequentially even if the CPU has spare execution units.

**Critical chains in current implementations**:
- ADD: 4-instruction chain (add -> adc -> adc -> adc), ~4 cycles
- SUB: 4-instruction chain per limb with borrow, ~8 cycles (borrow requires cmp)
- MUL: Multiple independent partial products feed into dependent accumulations
- Shifts: Deep select chains create long sequential dependencies

**Optimization signal**: Replacing sequential dependency chains with parallel
independent operations can improve ILP (instruction-level parallelism).

### 3. Carry Flag (CF) Chain Integrity

The ADD implementation uses x86 `ADD + ADC + ADC + ADC` which relies on the
carry flag (CF) propagating through consecutive instructions. Any instruction
between them that modifies EFLAGS (most ALU ops do) breaks the chain.

The current code uses `protectUnsafeValue()` to materialize all operands into
variables **before** the ADD/ADC chain, preventing lazy expression lowering from
inserting flag-clobbering instructions.

**Optimization constraint**: Any alternative ADD implementation must either
preserve this CF chain invariant, or use a different carry propagation strategy.

### 4. Runtime Call Overhead

A `call` instruction in dMIR has hidden costs:
- All caller-saved registers must be spilled/reloaded (~6 GPR saves)
- Function call overhead (~5 cycles for call+ret)
- Disrupts instruction scheduling and branch prediction

**Optimization signal**: Converting a runtime call to inline dMIR (e.g. inline
DIV instead of calling intx library) can improve performance IF the inline
sequence is short enough, but will increase dMIR count and RA pressure.

### 5. Select Chain Cost

`select` instructions (CMOVcc on x86) have a unique cost profile:
- 2-3 x86 instructions each
- Creates a data dependency (CMOVcc depends on flags AND both operands)
- Long select chains serialize execution

**Optimization signal**: Current SHL/SHR/SAR use ~15-96 select instructions.
Replacing select chains with computed indices or branch-based implementations
could improve performance for predictable shift patterns.

### 6. Compile-Time Cost (RA Pressure)

Dense dMIR sequences with many live values cause the register allocator to run
slowly (superlinear cost). This affects JIT compilation latency, not runtime
execution speed. The `isRAExpensiveOpcode()` heuristic in `evm_analyzer.h`
tracks this:

| EVM Opcode | Why RA-Expensive | Source |
|---|---|---|
| MUL (0x02) | ~80 dMIR, heavy partial-product fan-out | evm_analyzer.h:80 |
| SIGNEXTEND (0x0B) | ~21 Selects, two dependency chain loops | evm_analyzer.h:81 |
| SHL (0x1B) | ~92 Selects, nested J,K loops | evm_analyzer.h:82 |
| SHR (0x1C) | ~96 Selects, nested J,K loops | evm_analyzer.h:83 |
| SAR (0x1D) | ~52 Selects, sign-extended variant | evm_analyzer.h:84 |

If an optimization reduces dMIR count enough, these opcodes may no longer trigger
JIT fallback, which is itself a significant performance improvement (JIT vs interpreter).

---

## Worked Example: Comparing Two ADD Implementations

### Current Implementation (from `handleBinaryArithmetic<BO_ADD>`)

```
// Protect all operands first (prevent CF clobber)
$a[0..3] = dassign(extract_limbs(A))     // 4x dassign
$b[0..3] = dassign(extract_limbs(B))     // 4x dassign
$r[0] = dassign(add($a[0], $b[0]))       // add + dassign
$r[1] = dassign(adc($a[1], $b[1], 0))   // adc + dassign
$r[2] = dassign(adc($a[2], $b[2], 0))   // adc + dassign
$r[3] = dassign(adc($a[3], $b[3], 0))   // adc + dassign
```

**Cost breakdown**:
| dMIR type | Count | x86 factor | x86 total |
|---|---|---|---|
| dassign (protect) | 8 | 0-1 | ~4 (some coalesced) |
| add | 1 | 1 | 1 |
| adc | 3 | 2 | 6 |
| dassign (result) | 4 | 0-1 | ~2 |
| **Total** | **16** | | **~13 x86** |

Dependency chain: add -> adc -> adc -> adc = 4 cycles critical path.
Register pressure: 8 inputs + 4 outputs = 12 peak live vregs (manageable).

### Hypothetical Alternative: SUB-based (just for illustration)

If someone proposed implementing ADD as `A + B = A - (-B)` using per-limb negate+sub:

```
$b_neg[0..3] = xor($b[0..3], 0xFFFFFFFFFFFFFFFF)  // 4x xor
$one = const(i64, 1)
// Add 1 to complete two's complement: need carry chain anyway
$b_neg[0] = add($b_neg[0], $one)
// ... carry propagation needed, same complexity as original
```

This would be **worse**: same carry chain requirement, plus 4 extra XOR instructions.
No improvement.

### Hypothetical Alternative: Widening Approach

If the x86 backend supported 128-bit ADD (which it doesn't natively, but
hypothetically via SSE):

```
// Pack into 2x128-bit and use PADDQ
// Not feasible: PADDQ doesn't propagate carries between 64-bit lanes
```

This illustrates why the current ADD+ADC chain is already near-optimal for x86.

---

## Source Reference

For current implementation weights used by the JIT suitability checker:
`MIR_OPCODE_WEIGHT[256]` in `src/compiler/evm_frontend/evm_analyzer.h:31`.

Note: this weight table reflects the **current** handler implementations. When you
optimize a handler and change its dMIR output count, this table should also be
updated to match.
