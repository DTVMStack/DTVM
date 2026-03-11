# dMIR Cost Model and Performance Evaluation

This document provides the cost model for evaluating the performance impact of
EVM bytecode sequences through the dMIR compilation pipeline.

Source: `src/compiler/evm_frontend/evm_analyzer.h`.

## MIR Opcode Weight Table

The compiler uses `MIR_OPCODE_WEIGHT[256]` to estimate the dMIR instruction
count generated per EVM opcode. This drives JIT suitability analysis.

```
Hex   Opcode         Weight   Notes
---------------------------------------------------------------
0x00  STOP           5        Runtime call
0x01  ADD            12       4-limb add/adc chain
0x02  MUL            80       Schoolbook 4x4 partial products
0x03  SUB            20       4-limb sub with borrow propagation
0x04  DIV            5        Runtime call (intx)
0x05  SDIV           5        Runtime call (intx)
0x06  MOD            5        Runtime call (intx)
0x07  SMOD           5        Runtime call (intx)
0x08  ADDMOD         5        Runtime call (intx)
0x09  MULMOD         5        Runtime call (intx)
0x0A  EXP            5        Runtime call (but internally loop-heavy)
0x0B  SIGNEXTEND     20       ~21 select chains, two dependency loops

0x10  LT             12       4-limb comparison with select chain
0x11  GT             12       4-limb comparison with select chain
0x12  SLT            12       Signed variant of LT
0x13  SGT            12       Signed variant of GT
0x14  EQ             12       4-limb equality check with AND chain
0x15  ISZERO         8        3x OR + 1x CMP
0x16  AND            8        4x per-limb AND
0x17  OR             8        4x per-limb OR
0x18  XOR            8        4x per-limb XOR
0x19  NOT            8        4x per-limb XOR with all-ones
0x1A  BYTE           8        Select + shift chain
0x1B  SHL            15       Shift decomposition + select chains
0x1C  SHR            15       Shift decomposition + select chains
0x1D  SAR            15       Shift decomposition + sign extension
0x1E  CLZ            8        Count leading zeros

0x20  KECCAK256      5        Runtime call

0x30  ADDRESS        5        Runtime call
0x31  BALANCE        5        Runtime call
0x32  ORIGIN         5        Runtime call
0x33  CALLER         5        Runtime call
0x34  CALLVALUE      5        Runtime call
0x35  CALLDATALOAD   5        Runtime call
0x36  CALLDATASIZE   5        Runtime call
0x37  CALLDATACOPY   8        Runtime call with memory
0x38  CODESIZE       5        Runtime call
0x39  CODECOPY       8        Runtime call with memory
0x3A  GASPRICE       5        Runtime call
0x3B  EXTCODESIZE    5        Runtime call
0x3C  EXTCODECOPY    8        Runtime call with memory
0x3D  RETURNDATASIZE 5        Runtime call
0x3E  RETURNDATACOPY 8        Runtime call with memory
0x3F  EXTCODEHASH    5        Runtime call

0x40  BLOCKHASH      5        Runtime call
0x41  COINBASE       5        Runtime call
0x42  TIMESTAMP      5        Runtime call
0x43  NUMBER         5        Runtime call
0x44  PREVRANDAO     5        Runtime call
0x45  GASLIMIT       5        Runtime call
0x46  CHAINID        5        Runtime call
0x47  SELFBALANCE    5        Runtime call
0x48  BASEFEE        5        Runtime call
0x49  BLOBHASH       5        Runtime call
0x4A  BLOBBASEFEE    5        Runtime call

0x50  POP            2        Stack pointer adjustment
0x51  MLOAD          8        Memory access + bswap
0x52  MSTORE         8        Memory access + bswap
0x53  MSTORE8        8        Memory access
0x54  SLOAD          5        Runtime call (storage)
0x55  SSTORE         5        Runtime call (storage)
0x56  JUMP           5        Jump table lookup
0x57  JUMPI          5        Condition test + jump
0x58  PC             5        Compile-time constant
0x59  MSIZE          5        Runtime call
0x5A  GAS            5        Memory load
0x5B  JUMPDEST       2        Basic block boundary
0x5C  TLOAD          5        Runtime call (transient storage)
0x5D  TSTORE         5        Runtime call (transient storage)
0x5E  MCOPY          8        Runtime call with memory
0x5F  PUSH0          4        4x const(0)

0x60-0x7F  PUSH1-32  4 each   4x const(i64)
0x80-0x8F  DUP1-16   4 each   Stack load
0x90-0x9F  SWAP1-16  4 each   Stack load+store

0xA0-0xA4  LOG0-4    8 each   Runtime call

0xF0  CREATE         5        Runtime call
0xF1  CALL           5        Runtime call
0xF2  CALLCODE       5        Runtime call
0xF3  RETURN         5        Runtime call + return
0xF4  DELEGATECALL   5        Runtime call
0xF5  CREATE2        5        Runtime call
0xFA  STATICCALL     5        Runtime call
0xFD  REVERT         5        Runtime call
0xFF  SELFDESTRUCT   5        Runtime call
```

All undefined opcodes have weight 2.

## RA-Expensive Opcodes

Certain EVM opcodes generate dMIR structures that cause superlinear register
allocation cost when they appear in high density within a single basic block:

| Opcode | Hex | Why Expensive |
|---|---|---|
| MUL | 0x02 | ~50-60 MIR instructions, heavy partial-product fan-out across 10 evm_umul128 |
| SIGNEXTEND | 0x0B | ~21 SelectInstruction chains, two dependency chain loops |
| SHL | 0x1B | ~92 SelectInstruction chains, nested J,K component loops |
| SHR | 0x1C | ~96 SelectInstruction chains, nested J,K component loops |
| SAR | 0x1D | ~52 SelectInstruction chains, sign-extended variant |

Detection heuristic (`isRAExpensiveOpcode`): if more than a threshold number of
these appear consecutively (ignoring DUP/SWAP), the JIT may fall back to the
interpreter.

## x86 Expansion Factors

Average x86 instruction count per dMIR instruction, by category:

| dMIR Category | x86 Instructions | Notes |
|---|---|---|
| Simple binary (add, sub, and, or, xor) | 1 | Direct 1:1 mapping |
| adc | 2 | COPY + ADC (carry chain) |
| mul | 1 | IMUL64rr |
| div/rem | 4-5 | RAX/RDX setup + DIV + result copy |
| shifts (immediate) | 1 | SHL/SHR/SAR with immediate |
| shifts (variable) | 3 | COPY to CL + KILL + SHLrCL |
| cmp | 2 | CMP + SETcc |
| select | 2-3 | TEST + CMOVcc (or fused with cmp) |
| evm_umul128_lo | 4 | COPY to RAX + MUL64r + 2x COPY result |
| evm_umul128_hi | 0-1 | Reuses RDX from preceding MUL |
| load/store | 1 | MOV from/to memory |
| bswap | 1 | BSWAP64r |
| const | 1 | MOV immediate (or XOR for zero) |
| dread/dassign | 0-1 | COPY (often coalesced away) |
| call | N+2 | N argument moves + CALL + result copy |
| br | 1 | JMP |
| br_if | 2 | TEST + Jcc |
| conversion (trunc/sext/uext) | 0-1 | Subreg extract or MOVSX/MOVZX |
| fpabs/fpneg | 3 | Bitwise manipulation via int regs |
| fpsqrt | 1 | SQRT (high latency) |
| fpround | 1 | ROUNDSS/ROUNDSD |
| fpmin/fpmax | 10-15 | NaN handling with multiple basic blocks |

## Performance Evaluation Framework

### Step 1: Estimate dMIR Count

For a given EVM bytecode sequence, sum `MIR_OPCODE_WEIGHT[opcode]` for each instruction:

```
total_dmir = sum(MIR_OPCODE_WEIGHT[opcode] for opcode in bytecode)
```

### Step 2: Estimate x86 Count

Apply expansion factors per dMIR instruction type. For a rough estimate:

```
total_x86 ≈ total_dmir × 1.3   (average expansion factor)
```

For more precise estimates, categorize the dMIR instructions:

```
total_x86 = count_simple × 1.0
           + count_adc × 2.0
           + count_div × 4.5
           + count_shift_var × 3.0
           + count_cmp × 2.0
           + count_select × 2.5
           + count_umul128 × 3.0
           + count_call × (avg_args + 2)
           + count_other × 1.0
```

### Step 3: Identify Bottlenecks

Flag these patterns:

1. **Division-heavy code**: Each `sdiv/udiv/srem/urem` takes ~20-90 CPU cycles
2. **MUL-dense sequences**: Multiple consecutive MUL opcodes generate massive vreg pressure
3. **Select chain depth**: Deep select chains from SHL/SHR/SAR/SIGNEXTEND create long dependency chains
4. **Register pressure**: Count live vregs at peak; if > 14 (available GPRs minus RSP/RBP), expect spills
5. **Runtime call density**: Each call flushes caller-saved registers

### Step 4: JIT Suitability

The analyzer checks these thresholds (from `evm_analyzer.h`):

- **MAX_JIT_BYTECODE_SIZE**: Maximum bytecode length for JIT compilation
- **MAX_JIT_MIR_ESTIMATE**: Maximum estimated MIR instruction count
- **RA-expensive density**: Too many MUL/SHL/SHR/SAR/SIGNEXTEND in sequence

If thresholds are exceeded, the verdict is `ShouldFallback = true`, meaning the
code should run in the interpreter instead.

## Worked Example: Simple ERC-20 Transfer Snippet

```
PUSH1 0x00     ; weight 4
SLOAD          ; weight 5   (storage read)
DUP2           ; weight 4
ADD            ; weight 12  (4-limb add/adc)
PUSH1 0x00     ; weight 4
SSTORE         ; weight 5   (storage write)
```

### Cost Analysis

| Step | Metric | Value |
|---|---|---|
| Total MIR weight | sum of weights | 4+5+4+12+4+5 = 34 |
| Dominant cost | ADD (12 dMIR) | 35% of total |
| x86 estimate | 34 × 1.3 | ~44 instructions |
| RA-expensive? | No | No MUL/SHL/SHR |
| JIT suitable? | Yes | Well within thresholds |

### Bottleneck

The SLOAD and SSTORE are runtime calls; their actual execution time is dominated
by storage I/O, not instruction count. The ADD is the only compute-intensive
operation, generating a 4-instruction carry chain (ADD + 3x ADC) that executes
in ~4 cycles on modern x86.

## Worked Example: MUL-Heavy Sequence

```
PUSH32 <val>   ; weight 4
PUSH32 <val>   ; weight 4
MUL            ; weight 80  (schoolbook 4x4)
PUSH32 <val>   ; weight 4
MUL            ; weight 80
```

### Cost Analysis

| Step | Metric | Value |
|---|---|---|
| Total MIR weight | 4+4+80+4+80 = 172 | |
| x86 estimate | ~220 (MUL has higher expansion) | |
| RA-expensive count | 2 consecutive MULs | May stress RA |
| Register pressure | Very high during MUL | Expect spills |

Two back-to-back MULs generate ~160 dMIR instructions with heavy vreg fan-out.
The greedy RA will likely need to spill several values. This is still JIT-worthy
for short sequences, but a basic block full of such patterns may trigger fallback.
