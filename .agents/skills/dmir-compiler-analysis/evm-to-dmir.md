# EVM to dMIR Mapping Reference

This document provides detailed dMIR pseudocode expansions for each EVM opcode category.
All U256 values are represented as 4 x i64 limbs: `[lo, m1, m2, hi]` (little-endian).

**The pseudocode below is a summary. Always read the actual source code for
optimization work.** The source trace table below gives the exact file and function
for every EVM opcode.

## 0. Source Trace Table (Authoritative)

Every EVM opcode is dispatched in `EVMByteCodeVisitor::decode()` at
`src/action/evm_bytecode_visitor.h:108`. The visitor calls local `handle*()` wrappers
that pop/push the EVM stack and delegate to `EVMMirBuilder::handle*()` for dMIR generation.

### Arithmetic

| EVM Opcode | Hex | Visitor Dispatch (evm_bytecode_visitor.h) | Builder Function | Builder Location |
|---|---|---|---|---|
| STOP | 0x00 | :109 `handleStop()` | `EVMMirBuilder::handleStop` | evm_mir_compiler.cpp:879 |
| ADD | 0x01 | :113 `handleBinaryArithmetic<BO_ADD>()` | `EVMMirBuilder::handleBinaryArithmetic<BO_ADD>` | evm_mir_compiler.h:225 (template, inline) |
| MUL | 0x02 | :117 `handleMul()` | `EVMMirBuilder::handleMul` | evm_mir_compiler.cpp:1301 |
| SUB | 0x03 | :120 `handleBinaryArithmetic<BO_SUB>()` | `EVMMirBuilder::handleBinaryArithmetic<BO_SUB>` | evm_mir_compiler.h:225 (template, inline) |
| DIV | 0x04 | :122 `handleDiv()` | `EVMMirBuilder::handleDiv` | evm_mir_compiler.cpp:1400 |
| SDIV | 0x05 | :125 `handleSDiv()` | `EVMMirBuilder::handleSDiv` | evm_mir_compiler.cpp:1408 |
| MOD | 0x06 | :128 `handleMod()` | `EVMMirBuilder::handleMod` | evm_mir_compiler.cpp:1416 |
| SMOD | 0x07 | :131 `handleSMod()` | `EVMMirBuilder::handleSMod` | evm_mir_compiler.cpp:1424 |
| ADDMOD | 0x08 | :134 `handleAddMod()` | `EVMMirBuilder::handleAddMod` | evm_mir_compiler.cpp:1432 |
| MULMOD | 0x09 | :137 `handleMulMod()` | `EVMMirBuilder::handleMulMod` | evm_mir_compiler.cpp:1442 |
| EXP | 0x0A | :140 `handleExp()` | `EVMMirBuilder::handleExp` | evm_mir_compiler.cpp:1450 |
| SIGNEXTEND | 0x0B | :143 `handleSignextend()` | `EVMMirBuilder::handleSignextend` | evm_mir_compiler.cpp:2348 |

### Comparison

| EVM Opcode | Hex | Visitor Dispatch | Builder Function | Builder Location |
|---|---|---|---|---|
| LT | 0x10 | :147 `handleCompare<CO_LT>()` | `handleCompareOp<CO_LT>` -> `handleCompareGT_LT` | .h:311 (template) -> .cpp:1784 |
| GT | 0x11 | :150 `handleCompare<CO_GT>()` | `handleCompareOp<CO_GT>` -> `handleCompareGT_LT` | .h:311 -> .cpp:1784 |
| SLT | 0x12 | :153 `handleCompare<CO_LT_S>()` | `handleCompareOp<CO_LT_S>` -> `handleCompareGT_LT` | .h:311 -> .cpp:1784 |
| SGT | 0x13 | :156 `handleCompare<CO_GT_S>()` | `handleCompareOp<CO_GT_S>` -> `handleCompareGT_LT` | .h:311 -> .cpp:1784 |
| EQ | 0x14 | :159 `handleCompare<CO_EQ>()` | `handleCompareOp<CO_EQ>` -> `handleCompareEQ` | .h:311 -> .cpp:1752 |
| ISZERO | 0x15 | :162 `handleCompare<CO_EQZ>()` | `handleCompareOp<CO_EQZ>` -> `handleCompareEQZ` | .h:311 -> .cpp:1720 |

### Bitwise

| EVM Opcode | Hex | Visitor Dispatch | Builder Function | Builder Location |
|---|---|---|---|---|
| AND | 0x16 | :164 `handleBitwiseOp<BO_AND>()` | `EVMMirBuilder::handleBitwiseOp<BO_AND>` | evm_mir_compiler.h:318 (template, inline) |
| OR | 0x17 | :167 `handleBitwiseOp<BO_OR>()` | `EVMMirBuilder::handleBitwiseOp<BO_OR>` | evm_mir_compiler.h:318 |
| XOR | 0x18 | :170 `handleBitwiseOp<BO_XOR>()` | `EVMMirBuilder::handleBitwiseOp<BO_XOR>` | evm_mir_compiler.h:318 |
| NOT | 0x19 | :174 `handleNot()` | `EVMMirBuilder::handleNot` | evm_mir_compiler.cpp:1856 |
| BYTE | 0x1A | :177 `handleByte()` | `EVMMirBuilder::handleByte` | evm_mir_compiler.cpp:2273 |
| SHL | 0x1B | :180 `handleShift<BO_SHL>()` | `handleShift<BO_SHL>` -> `handleLeftShift` | .h:341 -> .cpp:1880 |
| SHR | 0x1C | :183 `handleShift<BO_SHR_U>()` | `handleShift<BO_SHR_U>` -> `handleLogicalRightShift` | .h:341 -> .cpp:2014 |
| SAR | 0x1D | :186 `handleShift<BO_SHR_S>()` | `handleShift<BO_SHR_S>` -> `handleArithmeticRightShift` | .h:341 -> .cpp:2142 |
| CLZ | 0x1E | :189 `handleClz()` | `EVMMirBuilder::handleClz` | evm_mir_compiler.cpp:1873 |

### Stack

| EVM Opcode | Hex | Visitor Dispatch | Builder Function | Builder Location |
|---|---|---|---|---|
| POP | 0x50 | :192 `handlePop()` | (visitor-level only, pops eval stack) | evm_bytecode_visitor.h |
| PUSH0-32 | 0x5F-0x7F | :195-231 `handlePush(N)` | `EVMMirBuilder::handlePush` | evm_mir_compiler.cpp:1143 |
| DUP1-16 | 0x80-0x8F | :234-252 `handleDup(N)` | `EVMMirBuilder::stackGet` | evm_mir_compiler.cpp:855 |
| SWAP1-16 | 0x90-0x9F | :255-273 `handleSwap(N)` | `EVMMirBuilder::stackGet/stackSet` | evm_mir_compiler.cpp:835/855 |

### Memory

| EVM Opcode | Hex | Visitor Dispatch | Builder Function | Builder Location |
|---|---|---|---|---|
| MLOAD | 0x51 | :471 | `EVMMirBuilder::handleMLoad` | evm_mir_compiler.cpp:2690 |
| MSTORE | 0x52 | :478 | `EVMMirBuilder::handleMStore` | evm_mir_compiler.cpp:2734 |
| MSTORE8 | 0x53 | :485 | `EVMMirBuilder::handleMStore8` | evm_mir_compiler.cpp:2793 |
| MCOPY | 0x5E | :526 | `EVMMirBuilder::handleMCopy` | evm_mir_compiler.cpp:2838 |
| MSIZE | 0x59 | :506 | `EVMMirBuilder::handleMSize` | evm_mir_compiler.cpp:2642 |

### Storage

| EVM Opcode | Hex | Visitor Dispatch | Builder Function | Builder Location |
|---|---|---|---|---|
| SLOAD | 0x54 | :492 | `EVMMirBuilder::handleSLoad` | evm_mir_compiler.cpp:3183 |
| SSTORE | 0x55 | :499 | `EVMMirBuilder::handleSStore` | evm_mir_compiler.cpp:3195 |
| TLOAD | 0x5C | :512 | `EVMMirBuilder::handleTLoad` | evm_mir_compiler.cpp:3207 |
| TSTORE | 0x5D | :519 | `EVMMirBuilder::handleTStore` | evm_mir_compiler.cpp:3212 |

### Environment

| EVM Opcode | Hex | Builder Function | Builder Location |
|---|---|---|---|
| ADDRESS | 0x30 | `handleAddress` | evm_mir_compiler.cpp:2474 |
| BALANCE | 0x31 | `handleBalance` | evm_mir_compiler.cpp:2479 |
| ORIGIN | 0x32 | `handleOrigin` | evm_mir_compiler.cpp:2492 |
| CALLER | 0x33 | `handleCaller` | evm_mir_compiler.cpp:2497 |
| CALLVALUE | 0x34 | `handleCallValue` | evm_mir_compiler.cpp:2502 |
| CALLDATALOAD | 0x35 | `handleCallDataLoad` | evm_mir_compiler.cpp:2508 |
| CALLDATASIZE | 0x36 | `handleCallDataSize` | evm_mir_compiler.cpp:2521 |
| CALLDATACOPY | 0x37 | `handleCallDataCopy` | evm_mir_compiler.cpp:3933 |
| CODESIZE | 0x38 | `handleCodeSize` | evm_mir_compiler.cpp:2526 |
| CODECOPY | 0x39 | `handleCodeCopy` | evm_mir_compiler.cpp:2531 |
| GASPRICE | 0x3A | `handleGasPrice` | evm_mir_compiler.cpp:2516 |
| EXTCODESIZE | 0x3B | `handleExtCodeSize` | evm_mir_compiler.cpp:2551 |
| EXTCODECOPY | 0x3C | `handleExtCodeCopy` | evm_mir_compiler.cpp:3953 |
| RETURNDATASIZE | 0x3D | `handleReturnDataSize` | evm_mir_compiler.cpp:4000 |
| RETURNDATACOPY | 0x3E | `handleReturnDataCopy` | evm_mir_compiler.cpp:3977 |
| EXTCODEHASH | 0x3F | `handleExtCodeHash` | evm_mir_compiler.cpp:2565 |
| BLOCKHASH | 0x40 | `handleBlockHash` | evm_mir_compiler.cpp:2579 |
| COINBASE | 0x41 | `handleCoinBase` | evm_mir_compiler.cpp:2587 |
| TIMESTAMP | 0x42 | `handleTimestamp` | evm_mir_compiler.cpp:2592 |
| NUMBER | 0x43 | `handleNumber` | evm_mir_compiler.cpp:2597 |
| PREVRANDAO | 0x44 | `handlePrevRandao` | evm_mir_compiler.cpp:2602 |
| GASLIMIT | 0x45 | `handleGasLimit` | evm_mir_compiler.cpp:2607 |
| CHAINID | 0x46 | `handleChainId` | evm_mir_compiler.cpp:2612 |
| SELFBALANCE | 0x47 | `handleSelfBalance` | evm_mir_compiler.cpp:2617 |
| BASEFEE | 0x48 | `handleBaseFee` | evm_mir_compiler.cpp:2622 |
| BLOBHASH | 0x49 | `handleBlobHash` | evm_mir_compiler.cpp:2627 |
| BLOBBASEFEE | 0x4A | `handleBlobBaseFee` | evm_mir_compiler.cpp:2637 |
| PC | 0x58 | `handlePC` | evm_mir_compiler.cpp:2457 |
| GAS | 0x5A | `handleGas` | evm_mir_compiler.cpp:2466 |

### Control Flow

| EVM Opcode | Hex | Builder Function | Builder Location |
|---|---|---|---|
| JUMP | 0x56 | `handleJump` | evm_mir_compiler.cpp:1150 |
| JUMPI | 0x57 | `handleJumpI` | evm_mir_compiler.cpp:1185 |
| JUMPDEST | 0x5B | `handleJumpDest` | evm_mir_compiler.cpp:1255 |
| Jump table setup | -- | `createJumpTable` | evm_mir_compiler.cpp:956 |
| Constant jump | -- | `implementConstantJump` | evm_mir_compiler.cpp:1079 |
| Indirect jump | -- | `implementIndirectJump` | evm_mir_compiler.cpp:1090 |

### Calls and Creates

| EVM Opcode | Hex | Builder Function | Builder Location |
|---|---|---|---|
| CREATE | 0xF0 | `handleCreate` | evm_mir_compiler.cpp:2969 |
| CALL | 0xF1 | `handleCall` | evm_mir_compiler.cpp:3005 |
| CALLCODE | 0xF2 | `handleCallCode` | evm_mir_compiler.cpp:3032 |
| RETURN | 0xF3 | `handleReturn` | evm_mir_compiler.cpp:3058 |
| DELEGATECALL | 0xF4 | `handleDelegateCall` | evm_mir_compiler.cpp:3083 |
| CREATE2 | 0xF5 | `handleCreate2` | evm_mir_compiler.cpp:2985 |
| STATICCALL | 0xFA | `handleStaticCall` | evm_mir_compiler.cpp:3109 |
| REVERT | 0xFD | `handleRevert` | evm_mir_compiler.cpp:3134 |
| INVALID | 0xFE | `handleInvalid` | evm_mir_compiler.cpp:3157 |
| SELFDESTRUCT | 0xFF | `handleSelfDestruct` | evm_mir_compiler.cpp:3217 |

### Other

| EVM Opcode | Hex | Builder Function | Builder Location |
|---|---|---|---|
| KECCAK256 | 0x20 | `handleKeccak256` | evm_mir_compiler.cpp:3238 |
| LOG0-LOG4 | 0xA0-A4 | `handleLogWithTopics<N>` | evm_mir_compiler.cpp:2935 (template) |

### Gas Metering (Injected at chunk boundaries)

| Function | Location |
|---|---|
| `EVMMirBuilder::meterOpcode` | evm_mir_compiler.cpp:411 |
| `EVMMirBuilder::meterOpcodeRange` | evm_mir_compiler.cpp:426 |
| `EVMMirBuilder::meterGas` | evm_mir_compiler.cpp:489 |

### x86 Lowering Functions (for reference)

Each dMIR opcode is lowered by `X86CgLowering` in `src/compiler/target/x86/x86lowering.cpp`:

| dMIR opcode | x86 Lowering Function | Line |
|---|---|---|
| add/sub/mul/and/or/xor | `CgLowering::lowerBinaryOpExpr` (base) -> `fastEmit_rr` | lowering.h (generic) |
| not | `X86CgLowering::lowerNotExpr` | x86lowering.cpp:23 |
| sdiv/udiv/srem/urem | `X86CgLowering::lowerDivRemExpr` | x86lowering.cpp:95 |
| shl/sshr/ushr/rotl/rotr | `X86CgLowering::lowerShiftExpr` | x86lowering.cpp:197 |
| cmp | `X86CgLowering::lowerCmpExpr` | x86lowering.cpp:858 |
| adc | `X86CgLowering::lowerAdcExpr` | x86lowering.cpp:906 |
| evm_umul128_lo | `X86CgLowering::lowerEvmUmul128Expr` | x86lowering.cpp:946 |
| evm_umul128_hi | `X86CgLowering::lowerEvmUmul128HiExpr` | x86lowering.cpp:991 |
| select | `X86CgLowering::lowerSelectExpr` | x86lowering.cpp:999 |
| load | `X86CgLowering::lowerLoadExpr` | x86lowering.cpp:1159 |
| store | `X86CgLowering::lowerStoreStmt` | x86lowering.cpp:1195 |
| br | `X86CgLowering::lowerBrStmt` | x86lowering.cpp:1251 |
| br_if | `X86CgLowering::lowerBrIfStmt` | x86lowering.cpp:1258 |
| switch | `X86CgLowering::lowerSwitchStmt` | x86lowering.cpp:1291 |
| call/icall | `X86CgLowering::lowerCall` | x86lowering.cpp:1531 |
| return | `X86CgLowering::lowerReturnStmt` | x86lowering.cpp:1708 |
| trunc | `X86CgLowering::lowerIntTruncExpr` | x86lowering.cpp:392 |
| uext | `X86CgLowering::lowerUExtExpr` | x86lowering.cpp:408 |
| fpabs | `X86CgLowering::lowerFPAbsExpr` | x86lowering.cpp:33 |
| fpneg | `X86CgLowering::lowerFPNegExpr` | x86lowering.cpp:51 |
| fpsqrt | `X86CgLowering::lowerFPSqrtExpr` | x86lowering.cpp:60 |
| fpround_* | `X86CgLowering::lowerFPRoundExpr` | x86lowering.cpp:67 |
| fpmin/fpmax | `X86CgLowering::lowerFPMinMaxExpr` | x86lowering.cpp:260 |
| fpcopysign | `X86CgLowering::lowerFPCopySignExpr` | x86lowering.cpp:360 |
| sitofp | `X86CgLowering::lowerSIToFPExpr` | x86lowering.cpp:546 |
| uitofp | `X86CgLowering::lowerUIToFPExpr` | x86lowering.cpp:455 |
| fpext | `X86CgLowering::lowerFPExtExpr` | x86lowering.cpp:447 |
| fptrunc | `X86CgLowering::lowerFPTruncExpr` | x86lowering.cpp:451 |
| dread (variable) | `X86CgLowering::lowerVariable` | x86lowering.cpp:565 |
| const (int) | `X86CgLowering::X86MaterializeInt` | x86lowering.cpp:585/596 |
| const (float) | `X86CgLowering::X86MaterializeFP` | x86lowering.cpp:644 |

---

## Notation

- `$a[0..3]` = limbs of U256 operand `a` (lo, mid-lo, mid-hi, hi)
- `$r[0..3]` = limbs of result
- `%t` = temporary dMIR value (expression, not assigned to variable)
- `$v` = dMIR variable (assigned via `dassign`)
- All limb operations use type `i64` unless noted

---

## 1. Arithmetic

### ADD (0x01)

Handler: `handleBinaryArithmetic<BO_ADD>`

```
// Materialize all limbs into variables first (protect carry chain)
$a[0..3] = dassign(extract_limbs(A))
$b[0..3] = dassign(extract_limbs(B))

$r[0] = dassign(add($a[0], $b[0]))       // regular add, sets CF
$r[1] = dassign(adc($a[1], $b[1], 0))    // add-with-carry from CF
$r[2] = dassign(adc($a[2], $b[2], 0))    // carry chain continues
$r[3] = dassign(adc($a[3], $b[3], 0))    // carry chain continues
```

~12 dMIR instructions (4 extract + 4 ops + 4 dassign).
The `adc` instruction consumes the x86 CF flag from the preceding `add`/`adc`.

### SUB (0x03)

Handler: `handleBinaryArithmetic<BO_SUB>`

```
for I in 0..3:
    %diff1 = sub($a[I], $b[I])
    %diff2 = sub(%diff1, $borrow)
    $r[I]  = dassign(%diff2)

    if I < 3:
        %borrow1 = cmp(iult, $a[I], $b[I])
        %borrow2 = cmp(iult, %diff1, $borrow)
        %borrow1_64 = uext(%borrow1)
        %borrow2_64 = uext(%borrow2)
        $borrow = or(%borrow1_64, %borrow2_64)
```

~20 dMIR instructions. Borrow propagation uses explicit `cmp + or` (no hardware borrow flag).

### MUL (0x02)

Handler: `handleMul`

Schoolbook multiplication of 4x64 limbs. For 256-bit truncated result, only
partial products where `i + j < 4` are needed:

```
R[0] = P00_lo
R[1] = P00_hi + P01_lo + P10_lo
R[2] = P01_hi + P10_hi + P02_lo + P11_lo + P20_lo
R[3] = P02_hi + P11_hi + P20_hi + P03_lo + P12_lo + P21_lo + P30_lo
```

Each partial product uses `evm_umul128_lo` and `evm_umul128_hi`:

```
PLo[i][j] = evm_umul128_lo($a[i], $b[j])    // 64x64 -> low 64 bits
PHi[i][j] = evm_umul128_hi(PLo[i][j])        // extract high 64 bits

// R[0]: just P00_lo
$r[0] = PLo[0][0]

// R[1]: accumulate P00_hi + P01_lo + P10_lo using add/adc
%sum1 = add(PHi[0][0], PLo[0][1])
$r[1] = add(%sum1, PLo[1][0])  // simplified; actual uses adc chain

// R[2]: accumulate 5 terms
// R[3]: accumulate 7 terms
// (each accumulation is an add/adc chain)
```

~80 dMIR instructions total: 10 umul128_lo, 7 umul128_hi, ~30 add/adc for accumulation, plus dassign/protect.

### DIV (0x04), SDIV (0x05), MOD (0x06), SMOD (0x07)

Handler: `handleDiv`, `handleSDiv`, `handleMod`, `handleSMod`

These are **runtime calls** to `intx` library functions:

```
$result_ptr = call(RuntimeFunctions.GetDiv, $a_ptr, $b_ref)
// or GetSDiv, GetMod, GetSMod
$r[0..3] = load results from returned pointer
```

~5 dMIR instructions per operation.

### ADDMOD (0x08), MULMOD (0x09)

Handler: `handleAddMod`, `handleMulMod`

Runtime calls:

```
$result = call(RuntimeFunctions.GetAddMod, $a, $b, $modulus)
$result = call(RuntimeFunctions.GetMulMod, $a, $b, $modulus)
```

~5 dMIR instructions each.

### EXP (0x0A)

Handler: `handleExp`

Inline binary exponentiation with two paths:

- **Fast path**: exponent fits in single i64 limb (limbs 1-3 are zero)
- **Slow path**: full 256-bit exponent

Both paths use a square-and-multiply loop that calls `handleMul` (~80 dMIR each) in each iteration. Total cost depends heavily on exponent bit length. Estimated ~200-500+ dMIR for typical cases.

### SIGNEXTEND (0x0B)

Handler: `handleSignextend`

Extends sign bit from byte position `b` across all higher bits. Uses a chain of ~21 `select` instructions to handle each possible byte position (0-30) within the 4 limbs:

```
for each byte position in the 256-bit value:
    %sign_bit = extract bit 7 of the target byte
    %mask = select(%sign_bit, 0xFF...FF, 0x00...00) for each limb
    $r[I] = select(%in_range, masked_value, original[I])
```

~20 dMIR instructions, heavy on `select` chains.

---

## 2. Bitwise Operations

### AND (0x16), OR (0x17), XOR (0x18)

Handler: `handleBitwiseOp<BO_AND/BO_OR/BO_XOR>`

Simple per-limb operation:

```
for I in 0..3:
    $r[I] = dassign(and/or/xor($a[I], $b[I]))
```

~8 dMIR instructions.

### NOT (0x19)

Handler: `handleNot`

XOR each limb with all-ones:

```
%all_ones = const(i64, 0xFFFFFFFFFFFFFFFF)
for I in 0..3:
    $r[I] = dassign(xor($a[I], %all_ones))
```

~8 dMIR instructions.

### BYTE (0x1A)

Handler: `handleByte`

Extract byte at position `index` (0 = most significant) from U256 value. Uses component selection and shift:

```
%byte_index = 31 - index  // convert to little-endian byte offset
%limb_index = byte_index / 8
%byte_offset = (byte_index % 8) * 8

// Select the correct limb using select chain
%selected = select(%limb_index == 0, $v[0],
            select(%limb_index == 1, $v[1],
            select(%limb_index == 2, $v[2], $v[3])))

// Extract byte
$r[0] = and(ushr(%selected, %byte_offset), 0xFF)
$r[1..3] = const(i64, 0)
```

~8 dMIR instructions.

---

## 3. Shift Operations

### SHL (0x1B)

Handler: `handleShift<BO_SHL>` -> `handleLeftShift`

```
%is_large = cmp(iuge, shift_amount, 256)   // shift >= 256 -> all zeros
%shift_mod = urem(shift_amount, 64)         // intra-limb shift
%comp_shift = udiv(shift_amount, 64)        // which limb to start from
%remaining = sub(64, %shift_mod)            // bits for carry

for I in 0..3:
    %src_idx = sub(I, %comp_shift)
    // Guard: if src_idx out of range, use 0
    %shifted = shl(value[src_idx], %shift_mod)
    %carry = ushr(value[src_idx - 1], %remaining)
    %combined = or(%shifted, %carry)
    $r[I] = select(%is_large, 0, select(%valid, %combined, 0))
```

~15 dMIR instructions per opcode, but the `select` chains for boundary conditions can balloon to ~92 instructions in the worst case (per the analyzer).

### SHR (0x1C)

Handler: `handleShift<BO_SHR_U>` -> `handleLogicalRightShift`

Similar to SHL but shifts right with zero fill. Mirror structure with `ushr` instead of `shl`.

~15 dMIR instructions, up to ~96 with full select chains.

### SAR (0x1D)

Handler: `handleShift<BO_SHR_S>` -> `handleArithmeticRightShift`

Like SHR but sign-extends from the high bit:

```
%sign_bit = ushr($v[3], 63)
%is_negative = cmp(ieq, %sign_bit, 1)
%large_result = select(%is_negative, 0xFFFFFFFFFFFFFFFF, 0)

// For shift < 256: same structure as SHR but using sshr for the top limb
// For shift >= 256: fill all limbs with %large_result
```

~15-52 dMIR instructions.

---

## 4. Comparison Operations

### LT (0x10), GT (0x11)

Handler: `handleCompareOp<CO_LT/CO_GT>` -> `handleCompareGT_LT`

Compare from most significant limb to least significant:

```
// Start from limb 3 (high), work down to limb 0 (low)
%result = 0
for I in 3..0:
    %gt = cmp(iugt, $a[I], $b[I])   // or iult for LT
    %eq = cmp(ieq, $a[I], $b[I])
    %result = select(%eq, %result, %gt)

$r[0] = uext(%result)
$r[1..3] = const(i64, 0)
```

~12 dMIR instructions.

### SLT (0x12), SGT (0x13)

Same as LT/GT but the **highest limb** uses signed comparison (`isgt`/`islt`), lower limbs use unsigned.

### EQ (0x14)

Handler: `handleCompareOp<CO_EQ>` -> `handleCompareEQ`

```
%eq0 = cmp(ieq, $a[0], $b[0])
%eq1 = cmp(ieq, $a[1], $b[1])
%eq2 = cmp(ieq, $a[2], $b[2])
%eq3 = cmp(ieq, $a[3], $b[3])
%result = and(%eq0, and(%eq1, and(%eq2, %eq3)))

$r[0] = uext(%result)
$r[1..3] = const(i64, 0)
```

~12 dMIR instructions.

### ISZERO (0x15)

Handler: `handleCompareOp<CO_EQZ>` -> `handleCompareEQZ`

```
%any = or($a[0], or($a[1], or($a[2], $a[3])))
%result = cmp(ieq, %any, 0)

$r[0] = uext(%result)
$r[1..3] = const(i64, 0)
```

~8 dMIR instructions.

---

## 5. Stack Operations

### PUSH0 (0x5F), PUSH1-PUSH32 (0x60-0x7F)

Handler: `handlePush`

Parse N bytes from bytecode, construct U256 constant:

```
$r[0] = const(i64, low_64_bits)
$r[1] = const(i64, mid_lo_64)
$r[2] = const(i64, mid_hi_64)
$r[3] = const(i64, high_64_bits)
```

~4 dMIR instructions. For PUSH0, all are zero.

### DUP1-DUP16 (0x80-0x8F)

Handler: `handleDup`

Duplicates the Nth stack element. Implemented via EVM stack load:

```
// Load U256 from stack memory at offset
$r[0..3] = load from EVMInstance stack memory
```

~4 dMIR instructions (4 loads from stack memory).

### SWAP1-SWAP16 (0x90-0x9F)

Handler: `handleSwap`

Swaps top of stack with Nth element:

```
// Load both, store both in swapped positions
$top[0..3] = load from stack[0]
$nth[0..3] = load from stack[N]
store $top[0..3] to stack[N]
store $nth[0..3] to stack[0]
```

~4 dMIR instructions (mainly stack pointer manipulation).

### POP (0x50)

Handler: `handlePop`

Just decrements the virtual stack pointer. ~2 dMIR instructions.

---

## 6. Memory Operations

### MLOAD (0x51)

Handler: `handleMLoad`

Load 32 bytes from EVM memory, byte-swap to big-endian:

```
// Ensure memory is large enough (may call runtime)
%addr = truncate_to_u32($offset[0])
call(evmEnsureMemory, %addr, 32)

// Load 4 x i64 and byte-swap (EVM memory is big-endian)
%ptr = add(memory_base, %addr)
for I in 3..0:  // reverse order for big-endian
    %raw = load(i64, %ptr + (3-I)*8)
    $r[I] = bswap(%raw)
```

~8 dMIR instructions.

### MSTORE (0x52)

Handler: `handleMStore`

Store 32 bytes to EVM memory with byte-swap:

```
%addr = truncate_to_u32($offset[0])
call(evmEnsureMemory, %addr, 32)
%ptr = add(memory_base, %addr)
for I in 3..0:
    %swapped = bswap($v[I])
    store(%swapped, %ptr + (3-I)*8)
```

~8 dMIR instructions.

### MSTORE8 (0x53)

Handler: `handleMStore8`

Store single byte. ~8 dMIR instructions.

### MCOPY (0x5E)

Handler: `handleMCopy`

Runtime call for memory copy. ~8 dMIR instructions.

---

## 7. Storage Operations

### SLOAD (0x54)

Handler: `handleSLoad`

```
call(evmSLoad, instance_ptr, $key_ptr) -> $result_ptr
$r[0..3] = load from result_ptr
```

~5 dMIR instructions. Dominated by the runtime call cost.

### SSTORE (0x55)

Handler: `handleSStore`

```
call(evmSStore, instance_ptr, $key_ptr, $value_ptr)
```

~5 dMIR instructions.

### TLOAD (0x5C), TSTORE (0x5D)

Transient storage. Same pattern as SLOAD/SSTORE with different runtime functions.

---

## 8. Environment Operations

All environment opcodes translate to runtime calls that return U256 values:

| EVM Opcode | Runtime Function | Notes |
|---|---|---|
| ADDRESS (0x30) | `evmGetAddress` | Returns 20-byte address as U256 |
| BALANCE (0x31) | `evmGetBalance` | Takes address, returns U256 |
| ORIGIN (0x32) | `evmGetOrigin` | |
| CALLER (0x33) | `evmGetCaller` | |
| CALLVALUE (0x34) | `evmGetCallValue` | |
| CALLDATALOAD (0x35) | `evmCallDataLoad` | Takes offset |
| CALLDATASIZE (0x36) | `evmCallDataSize` | |
| CODESIZE (0x38) | `evmCodeSize` | |
| GASPRICE (0x3A) | `evmGasPrice` | |
| EXTCODESIZE (0x3B) | `evmExtCodeSize` | |
| EXTCODEHASH (0x3F) | `evmExtCodeHash` | |
| BLOCKHASH (0x40) | `evmBlockHash` | |
| COINBASE (0x41) | `evmCoinBase` | |
| TIMESTAMP (0x42) | `evmTimestamp` | |
| NUMBER (0x43) | `evmNumber` | |
| PREVRANDAO (0x44) | `evmPrevRandao` | |
| GASLIMIT (0x45) | `evmGasLimit` | |
| CHAINID (0x46) | `evmChainId` | |
| SELFBALANCE (0x47) | `evmSelfBalance` | |
| BASEFEE (0x48) | `evmBaseFee` | |
| BLOBHASH (0x49) | `evmBlobHash` | |
| BLOBBASEFEE (0x4A) | `evmBlobBaseFee` | |
| MSIZE (0x59) | `evmMSize` | |
| GAS (0x5A) | load from EVMInstance | Direct memory read |
| PC (0x58) | `const` | Compile-time known |

Pattern: ~5 dMIR instructions each (call setup + result load).

---

## 9. Control Flow

### JUMP (0x56)

Handler: `handleJump`

EVM JUMP requires a jump destination table. The compiler pre-analyzes all JUMPDEST locations and builds a hash table:

```
// Constant jump (target known at compile time):
br @target_block

// Indirect jump (target from stack):
%dest = $target[0]  // low limb only
switch(%dest, @default_invalid, [dest1: @bb1, dest2: @bb2, ...])
```

~5 dMIR instructions.

### JUMPI (0x57)

Handler: `handleJumpI`

Conditional jump:

```
%cond_any = or($cond[0], or($cond[1], or($cond[2], $cond[3])))
%is_nonzero = cmp(ine, %cond_any, 0)
br_if(%is_nonzero, @jump_target, @fallthrough)
```

~5 dMIR instructions for the condition test, plus the jump logic from JUMP.

### JUMPDEST (0x5B)

Creates a new basic block. ~2 dMIR instructions.

### STOP (0x00)

```
call(evmStop, instance_ptr)
return
```

### RETURN (0xF3), REVERT (0xFD)

```
call(evmReturn/evmRevert, instance_ptr, offset, length)
return
```

~5 dMIR instructions.

---

## 10. Call Operations

### CALL (0xF1), STATICCALL (0xFA), DELEGATECALL (0xF4), CALLCODE (0xF2)

All translate to runtime calls with multiple U256 arguments:

```
$result = call(evmHandleCall, gas, to_addr, value, args_offset, args_size,
               ret_offset, ret_size)
```

~5 dMIR instructions (dominated by runtime call overhead).

### CREATE (0xF0), CREATE2 (0xF5)

```
$result = call(evmCreate/evmCreate2, value, offset, size [, salt])
```

~5 dMIR instructions.

---

## 11. Log Operations

### LOG0-LOG4 (0xA0-0xA4)

```
call(evmLog0/evmLog1/.../evmLog4, offset, size, [topic0, ..., topicN])
```

~8 dMIR instructions per LOG variant.

---

## 12. Hash Operations

### KECCAK256 (0x20)

```
$result = call(evmKeccak256, offset, length)
```

~5 dMIR instructions.

---

## 13. Copy Operations

### CALLDATACOPY (0x37), CODECOPY (0x39), EXTCODECOPY (0x3C), RETURNDATACOPY (0x3E)

All are runtime calls:

```
call(evmCallDataCopy/evmCodeCopy/..., dest_offset, src_offset, length)
```

~8 dMIR instructions each.

---

## 14. Gas Metering

Gas metering is injected at chunk boundaries (not per-opcode). Each gas check:

```
%gas_remaining = load(i64, instance + gas_offset)
%new_gas = sub(%gas_remaining, chunk_cost)
%out_of_gas = cmp(islt, %new_gas, 0)
br_if(%out_of_gas, @out_of_gas_handler, @continue)
store(%new_gas, instance + gas_offset)
```

~5 dMIR instructions per gas check point.
