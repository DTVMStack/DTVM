# dMIR to x86 Lowering Reference

This document describes how each dMIR instruction is lowered to x86 machine instructions
through the multipass compiler pipeline.

**For optimization work, always read the actual lowering code.** The x86 lowering
function for each dMIR opcode is listed in the source trace table in
[evm-to-dmir.md](evm-to-dmir.md) Section 0 (x86 Lowering Functions).

Source: `src/compiler/target/x86/x86lowering.cpp`, `src/compiler/cgir/lowering.h`.

## Pipeline: dMIR -> CGIR -> x86

```
dMIR instruction
  |  X86CgLowering::lowerExpr() / lowerStmt()
  v
CGIR instruction (virtual registers)
  |  X86CgPeephole (minor optimizations)
  |  Register Allocation (FastRA or CgRAGreedy)
  |  PrologEpilogInserter
  |  ExpandPostRAPseudos
  v
CGIR instruction (physical registers)
  |  X86MCLowering -> X86MCInstLower::lower()
  v
llvm::MCInst -> x86 machine code bytes
```

## Virtual Register System

### MIR Variables -> CGIR Virtual Registers

Each dMIR `Variable(VarIdx)` maps to a CGIR virtual register:

```
MIR Variable ($0, $1, ...)
  |  CgLowering::_var_reg_map[var_idx]
  v
CGIR Virtual Register (e.g., %vreg0, %vreg1, ...)
```

`getOrCreateVarReg(var_idx, reg_class)` allocates a new CGIR vreg on first use.

### MIR Expressions -> CGIR Virtual Registers

Each dMIR expression result also gets a vreg:

```
MIR Instruction (result of add, mul, etc.)
  |  CgLowering::_expr_reg_map[MInstruction*]
  v
CGIR Virtual Register
```

### Register Allocation

Two allocators available:

- **FastRA** (`src/compiler/cgir/pass/fast_ra.cpp`): Linear scan, fast, used by default
- **CgRAGreedy** (`src/compiler/cgir/pass/reg_alloc_greedy.cpp`): Greedy with live-range splitting, used for complex functions

Both use `CgVirtRegMap` to track:
- `Virt2PhysMap`: virtual register -> physical x86 register
- `Virt2StackSlotMap`: virtual register -> stack spill slot

`CgVirtRegRewriter` replaces all virtual registers with physical registers.

### x86 Register Classes

| Register Class | Registers | Used For |
|---|---|---|
| GR64 | RAX, RBX, RCX, RDX, RSI, RDI, R8-R15, RBP, RSP | 64-bit integer |
| GR32 | EAX, EBX, ECX, EDX, ESI, EDI, R8D-R15D | 32-bit integer |
| FR64 | XMM0-XMM15 | 64-bit float (double) |
| FR32 | XMM0-XMM15 | 32-bit float |

---

## Instruction Lowering Details

### Unary Operations

#### clz (count leading zeros)

```
dMIR:  %r = clz(i32/i64, %op)
x86:   BSR reg, op      ; bit scan reverse
       XOR reg, 31/63   ; convert to CLZ
       ; or LZCNT if available
```

2-3 x86 instructions.

#### ctz (count trailing zeros)

```
dMIR:  %r = ctz(i32/i64, %op)
x86:   BSF reg, op      ; bit scan forward
       ; or TZCNT if available
```

1-2 x86 instructions.

#### not (bitwise NOT)

```
dMIR:  %r = not(i32/i64, %op)
x86:   XOR reg, 0xFFFFFFFF/0xFFFFFFFFFFFFFFFF
```

Lowered via `fastEmit_ri_(VT, ISD::XOR, Operand, AllOnes)`. 1 x86 instruction.

#### popcnt

```
dMIR:  %r = popcnt(i32/i64, %op)
x86:   POPCNT reg, op
```

1 x86 instruction.

#### bswap (byte swap)

```
dMIR:  %r = bswap(i64, %op)
x86:   BSWAP64r reg
```

1 x86 instruction. Used heavily for EVM MLOAD/MSTORE (big-endian conversion).

#### fpabs

```
dMIR:  %r = fpabs(f32/f64, %op)
x86:   MOV32ri/MOV64ri mask_reg, 0x7FFFFFFF/0x7FFFFFFFFFFFFFFF
       MOVD/MOVQ  fp_mask, mask_reg        ; int -> xmm
       ANDPS/ANDPD result, fp_mask, op     ; clear sign bit
```

3 x86 instructions.

#### fpneg

```
dMIR:  %r = fpneg(f32/f64, %op)
x86:   MOVD/MOVQ  int_reg, op   ; xmm -> int
       XOR int_reg, sign_bit    ; flip sign bit
       MOVD/MOVQ  result, int_reg ; int -> xmm
```

3 x86 instructions.

#### fpsqrt

```
dMIR:  %r = fpsqrt(f32/f64, %op)
x86:   SQRTSSr/SQRTSDr result, op
```

1 x86 instruction (but high latency: ~12-20 cycles).

#### fpround_ceil / fpround_floor / fpround_trunc / fpround_nearest

```
dMIR:  %r = fpround_ceil(f32/f64, %op)
x86:   ROUNDSSr/ROUNDSDr result, op, <rounding_mode>
```

1 x86 instruction. Rounding modes: 0x0A (ceil), 0x09 (floor), 0x0B (trunc), 0x08 (nearest).

---

### Binary Operations

#### add

```
dMIR:  %r = add(i64, %lhs, %rhs)
x86:   ADD64rr dst, lhs, rhs
```

Via `fastEmit_rr(VT, VT, ISD::ADD, Op0, Op1)`. 1 x86 instruction.
For `i32`: `ADD32rr`. For immediate operand: `ADD64ri32`/`ADD32ri`.

#### sub

```
dMIR:  %r = sub(i64, %lhs, %rhs)
x86:   SUB64rr dst, lhs, rhs
```

1 x86 instruction.

#### mul

```
dMIR:  %r = mul(i64, %lhs, %rhs)
x86:   IMUL64rr dst, lhs, rhs
```

1 x86 instruction (~3-4 cycle latency).

#### adc (add with carry)

```
dMIR:  %r = adc(i64, %lhs, %rhs, %carry_placeholder)
x86:   COPY dst, lhs
       ADC64rr dst, rhs, dst   ; consumes CF from preceding ADD/ADC
```

Lowered by `X86CgLowering::lowerAdcExpr`. The carry placeholder is not used at x86 level; the hardware CF flag from the preceding `ADD`/`ADC` instruction is consumed directly.

2 x86 instructions (COPY + ADC).

#### sdiv / udiv / srem / urem

```
dMIR:  %r = sdiv(i64, %lhs, %rhs)
x86:   COPY RAX, lhs             ; move dividend to RAX
       CQO                        ; sign-extend RAX into RDX:RAX (signed)
       ; or XOR RDX, RDX          ; zero RDX (unsigned)
       IDIV64r rhs                ; RDX:RAX / rhs -> RAX=quotient, RDX=remainder
       ; or DIV64r for unsigned
       COPY dst, RAX              ; quotient (sdiv/udiv)
       ; or COPY dst, RDX         ; remainder (srem/urem)
```

4-5 x86 instructions. Division is the slowest integer operation (~20-90 cycles).

For i32: uses EAX/EDX, IDIV32r/DIV32r, CDQ instead of CQO.

| dMIR op | Sign extend | DIV instruction | Result register |
|---|---|---|---|
| sdiv | CQO | IDIV64r | RAX |
| srem | CQO | IDIV64r | RDX |
| udiv | XOR RDX,RDX | DIV64r | RAX |
| urem | XOR RDX,RDX | DIV64r | RDX |

#### and / or / xor

```
dMIR:  %r = and(i64, %lhs, %rhs)
x86:   AND64rr dst, lhs, rhs
```

1 x86 instruction each. For immediate: `AND64ri32`, `OR64ri32`, `XOR64ri32`.

#### shl / sshr / ushr

```
dMIR:  %r = shl(i64, %lhs, %rhs)
x86 (immediate shift):
       SHL64ri dst, lhs, imm

x86 (variable shift):
       COPY RCX, rhs             ; shift amount must be in CL
       KILL CL                   ; mark CL as used
       SHL64rCL dst, lhs         ; shift by CL
```

1 x86 instruction for immediate, 3 for variable shift (COPY + KILL + SHLrCL).

| dMIR op | Immediate x86 | Variable x86 |
|---|---|---|
| shl | SHL64ri / SHL32ri | SHL64rCL / SHL32rCL |
| sshr | SAR64ri / SAR32ri | SAR64rCL / SAR32rCL |
| ushr | SHR64ri / SHR32ri | SHR64rCL / SHR32rCL |
| rotl | ROL64ri / ROL32ri | ROL64rCL / ROL32rCL |
| rotr | ROR64ri / ROR32ri | ROR64rCL / ROR32rCL |

#### fpdiv

```
dMIR:  %r = fpdiv(f32/f64, %lhs, %rhs)
x86:   DIVSSrr/DIVSDrr dst, lhs, rhs
```

1 x86 instruction (~10-20 cycle latency).

#### fpmin / fpmax

Complex lowering with NaN handling:

```
x86:   SUBSSrr lhs, lhs, float_zero    ; canonicalize -0/+0
       SUBSSrr rhs, rhs, float_zero
       UCOMISSrr lhs, rhs               ; compare, set flags
       JNE @minmax_bb                    ; if unequal, use hardware min/max
       JP @nan_bb                        ; if parity, handle NaN
       ; equal case: merge sign bits
       ORPSrr/ANDPSrr result, lhs, rhs  ; ORPSrr for min, ANDPSrr for max
       JMP @done
@nan_bb:
       UCOMISSrr lhs, lhs               ; check if lhs is NaN
       COPY result, lhs
       JP @done                          ; if lhs is NaN, return it
@minmax_bb:
       MINSSrr/MAXSSrr result, lhs, rhs
@done:
```

~10-15 x86 instructions with multiple basic blocks for correct IEEE 754 behavior.

#### fpcopysign

```
x86:   ; Extract sign from rhs, magnitude from lhs
       MOVD/MOVQ int_rhs, rhs
       AND int_rhs, sign_mask            ; isolate sign bit
       MOVD/MOVQ int_lhs, lhs
       AND int_lhs, magnitude_mask       ; isolate magnitude
       OR int_result, int_lhs, int_rhs   ; combine
       MOVD/MOVQ result, int_result
```

~6 x86 instructions.

---

### Comparison and Selection

#### cmp

```
dMIR:  %r = cmp(<predicate>, type, %lhs, %rhs)

x86 (integer):
       CMP64rr lhs, rhs          ; or CMP32rr, TEST for eq/ne with 0
       SETcc dst                  ; set byte based on condition

x86 (float):
       UCOMISSrr/UCOMISDrr lhs, rhs
       SETcc dst
```

Predicate-to-x86 condition code mapping:

| dMIR predicate | x86 SETcc |
|---|---|
| ieq | SETE |
| ine | SETNE |
| iugt | SETA |
| iuge | SETAE |
| iult | SETB |
| iule | SETBE |
| isgt | SETG |
| isge | SETGE |
| islt | SETL |
| isle | SETLE |

2 x86 instructions (CMP + SETcc).

#### select

```
dMIR:  %r = select(type, %cond, %true_val, %false_val)

x86 (typical):
       TEST8rr cond, cond         ; or CMP if cond is from cmp
       CMOVNErr dst, false_val    ; conditional move if NE
       ; dst starts with true_val
```

When the condition comes from a `cmp` instruction, the lowering can fuse them:

```
x86 (fused with cmp):
       CMP64rr cmp_lhs, cmp_rhs
       CMOVcc dst, false_val     ; cc matching the cmp predicate
```

2-3 x86 instructions.

For `FCMP_OEQ` and `FCMP_UNE`, two condition checks are needed (NP+E or P+NE):

```
x86:   UCOMISSrr lhs, rhs
       SETNPr tmp1
       SETEr tmp2
       TEST8rr tmp1, tmp2         ; OEQ needs both NP and E
       CMOVNErr dst, false_val
```

4-5 x86 instructions for these special cases.

---

### EVM-Specific Instructions

#### evm_umul128_lo (64x64 -> 128, low 64 bits)

```
dMIR:  %r = evm_umul128_lo(i64, %lhs, %rhs)
x86:   COPY RAX, lhs             ; MUL uses RAX implicitly
       MUL64r rhs                ; RAX * rhs -> RDX:RAX
       COPY lo_result, RAX       ; low 64 bits
       COPY hi_result, RDX       ; high 64 bits (saved for umul128_hi)
```

4 x86 instructions. MUL64r latency: ~3-4 cycles.

#### evm_umul128_hi (extract high 64 bits)

```
dMIR:  %r = evm_umul128_hi(%umul128_lo_result)
x86:   ; reuses the RDX value from the preceding MUL64r
       ; just a register copy (or no-op if already in correct vreg)
       COPY result, hi_reg_from_umul128_lo
```

0-1 x86 instructions (relies on `Umul128HiRegs` map in the lowering pass).

---

### Memory Operations

#### load

```
dMIR:  %r = load(type, %addr)
x86:   MOV64rm dst, [addr]       ; for i64
       MOV32rm dst, [addr]       ; for i32
       MOVSSrm dst, [addr]       ; for f32
       MOVSDrm dst, [addr]       ; for f64
```

1 x86 instruction. May include offset: `MOV64rm dst, [base + offset]`.

For sub-word loads with extension:
- `load + sext`: `MOVSX64rm32` / `MOVSX32rm16` / `MOVSX32rm8`
- `load + uext`: `MOVZX32rm16` / `MOVZX32rm8`

#### store

```
dMIR:  store(type, %value, %addr)
x86:   MOV64mr [addr], value     ; for i64
       MOV32mr [addr], value     ; for i32
       MOVSSmr [addr], value     ; for f32
       MOVSDmr [addr], value     ; for f64
```

1 x86 instruction.

For sub-word stores with truncation:
- `trunc + store`: `MOV8mr` / `MOV16mr`

---

### Conversion Operations

#### trunc (narrow)

```
dMIR:  %r = trunc(i32, %op_i64)
x86:   ; typically a no-op or COPY (just use the lower 32 bits of the register)
       COPY dst_32, src_64_subreg
```

0-1 x86 instructions.

#### sext (sign extend)

```
dMIR:  %r = sext(i64, %op_i32)
x86:   MOVSX64rr32 dst, src
```

1 x86 instruction.

#### uext (zero extend)

```
dMIR:  %r = uext(i64, %op_i32)
x86:   MOVZX32rr dst, src        ; or MOV32rr (implicit zero-extend in x86-64)
```

1 x86 instruction.

#### sitofp / uitofp

```
dMIR:  %r = sitofp(f64, %op_i32)
x86:   CVTSI2SDrr dst, src
```

1 x86 instruction. Variants: CVTSI2SSrr (to f32), CVTSI2SD64rr (from i64).

#### wasm_fptosi / wasm_fptoui

```
dMIR:  %r = wasm_fptosi(i32, %op_f64)
x86:   CVTTSD2SIrr dst, src      ; truncating conversion
       ; + bounds check for WASM semantics (trap on overflow/NaN)
```

1-3 x86 instructions (conversion + optional bounds check).

#### fptrunc / fpext

```
dMIR:  %r = fptrunc(f32, %op_f64)
x86:   CVTSD2SSrr dst, src

dMIR:  %r = fpext(f64, %op_f32)
x86:   CVTSS2SDrr dst, src
```

1 x86 instruction each.

#### bitcast

```
dMIR:  %r = bitcast(f64, %op_i64)
x86:   MOVD64rr/MOVQ dst, src    ; move between int and FP registers
```

1 x86 instruction.

---

### Control Flow

#### br (unconditional branch)

```
dMIR:  br @target
x86:   JMP target
```

1 x86 instruction.

#### br_if (conditional branch)

```
dMIR:  br_if(%cond, @true_bb, @false_bb)
x86:   TEST8rr cond, cond         ; or reuse flags from preceding cmp
       JNE @true_bb
       ; fallthrough to @false_bb
```

2 x86 instructions (TEST + Jcc). If the condition comes from a `cmp`, the TEST may be elided.

#### switch

```
dMIR:  switch(%val, @default, [case1: @bb1, case2: @bb2, ...])
x86:   ; series of CMP + JE, or jump table lookup
       CMP64ri val, case1
       JE @bb1
       CMP64ri val, case2
       JE @bb2
       ...
       JMP @default
```

2 x86 instructions per case (CMP + JE), or O(1) with a jump table.

#### call

```
dMIR:  %r = call(ret_type, @func, %arg0, %arg1, ...)
x86:   ; ABI: args in RDI, RSI, RDX, RCX, R8, R9 (System V AMD64)
       MOV RDI, arg0
       MOV RSI, arg1
       ...
       CALL @func
       ; result in RAX (integer) or XMM0 (float)
       MOV dst, RAX
```

Variable number of x86 instructions: 1 per argument + CALL + result copy.

#### icall (indirect call)

Same as `call` but uses a register-indirect call:

```
x86:   CALL *reg
```

#### return

```
dMIR:  return %val
x86:   MOV RAX, val               ; (if returning a value)
       ; epilog: restore callee-saved regs, restore RSP, RET
       RET
```

1-5 x86 instructions (including epilog).

---

### Variable Assignment

#### dread (read variable)

```
dMIR:  %r = dread(type, var_idx)
x86:   ; maps to the vreg assigned to var_idx
       ; typically a COPY or no-op (just reference the vreg)
       COPY dst, var_reg
```

0-1 x86 instructions.

#### dassign (assign to variable)

```
dMIR:  dassign(%expr, var_idx)
x86:   COPY var_reg, expr_reg
```

1 x86 instruction (COPY, often eliminated by register coalescing).

---

## Composite Example: EVM ADD -> x86

```
EVM:  ADD  (a + b, both U256)

dMIR:
  // Extract 4 limbs each, protect into variables
  $a0 = dassign(extract a[0])      -> COPY
  $a1 = dassign(extract a[1])      -> COPY
  $a2 = dassign(extract a[2])      -> COPY
  $a3 = dassign(extract a[3])      -> COPY
  $b0 = dassign(extract b[0])      -> COPY
  $b1 = dassign(extract b[1])      -> COPY
  $b2 = dassign(extract b[2])      -> COPY
  $b3 = dassign(extract b[3])      -> COPY

  %t0 = add($a0, $b0)              -> ADD64rr
  $r0 = dassign(%t0)               -> COPY (may be coalesced)
  %t1 = adc($a1, $b1, 0)           -> COPY + ADC64rr
  $r1 = dassign(%t1)               -> COPY
  %t2 = adc($a2, $b2, 0)           -> COPY + ADC64rr
  $r2 = dassign(%t2)               -> COPY
  %t3 = adc($a3, $b3, 0)           -> COPY + ADC64rr
  $r3 = dassign(%t3)               -> COPY

x86 (after register allocation, many COPYs eliminated):
  ADD r0, a0, b0     ; sets CF
  ADC r1, a1, b1     ; reads CF, sets CF
  ADC r2, a2, b2     ; reads CF, sets CF
  ADC r3, a3, b3     ; reads CF

  ~4-8 x86 instructions (ADD + 3x ADC, plus any spill/reload)
```

## Composite Example: EVM EQ -> x86

```
EVM:  EQ  (a == b, both U256)

dMIR:
  %eq0 = cmp(ieq, $a[0], $b[0])   -> CMP64rr + SETE
  %eq1 = cmp(ieq, $a[1], $b[1])   -> CMP64rr + SETE
  %eq2 = cmp(ieq, $a[2], $b[2])   -> CMP64rr + SETE
  %eq3 = cmp(ieq, $a[3], $b[3])   -> CMP64rr + SETE
  %and01 = and(%eq0, %eq1)         -> AND8rr
  %and012 = and(%and01, %eq2)      -> AND8rr
  %result = and(%and012, %eq3)     -> AND8rr
  $r[0] = uext(%result)            -> MOVZX64rr8
  $r[1..3] = const(0)              -> XOR reg,reg (x3)

x86 total: ~14 instructions (4x CMP+SETE + 3x AND + MOVZX + 3x XOR)
```
