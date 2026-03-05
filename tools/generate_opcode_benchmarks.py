#!/usr/bin/env python3
"""
Opcode Microbenchmark Generator for EVM

This script generates EVM bytecode test cases specifically designed to measure
the execution cost of individual opcodes. It uses data-dependency chaining
and stack-balanced loop bodies to ensure:
1. No stack underflows or overflows during execution.
2. The JIT compiler (in DTVM) cannot optimize away the loops via dead-code elimination.

The output is formatted as Ethereum State Test JSONs, which can be directly
loaded and benchmarked by `evmone-bench`.
"""

import json
import os
import argparse
from typing import Dict, List, Any

# EVM Opcode hex values
OP_STOP = "00"
OP_ADD = "01"
OP_MUL = "02"
OP_SUB = "03"
OP_DIV = "04"
OP_SDIV = "05"
OP_MOD = "06"
OP_SMOD = "07"
OP_ADDMOD = "08"
OP_MULMOD = "09"
OP_EXP = "0a"
OP_SIGNEXTEND = "0b"

OP_LT = "10"
OP_GT = "11"
OP_SLT = "12"
OP_SGT = "13"
OP_EQ = "14"
OP_ISZERO = "15"
OP_AND = "16"
OP_OR = "17"
OP_XOR = "18"
OP_NOT = "19"
OP_BYTE = "1a"
OP_SHL = "1b"
OP_SHR = "1c"
OP_SAR = "1d"

OP_SHA3 = "20"

OP_ADDRESS = "30"
OP_BALANCE = "31"
OP_ORIGIN = "32"
OP_CALLER = "33"
OP_CALLVALUE = "34"
OP_CALLDATALOAD = "35"
OP_CALLDATASIZE = "36"
OP_CALLDATACOPY = "37"
OP_CODESIZE = "38"
OP_CODECOPY = "39"
OP_GASPRICE = "3a"
OP_EXTCODESIZE = "3b"
OP_EXTCODECOPY = "3c"
OP_RETURNDATASIZE = "3d"
OP_RETURNDATACOPY = "3e"
OP_EXTCODEHASH = "3f"

OP_BLOCKHASH = "40"
OP_COINBASE = "41"
OP_TIMESTAMP = "42"
OP_NUMBER = "43"
OP_DIFFICULTY = "44"
OP_GASLIMIT = "45"
OP_CHAINID = "46"
OP_SELFBALANCE = "47"
OP_BASEFEE = "48"

OP_POP = "50"
OP_MLOAD = "51"
OP_MSTORE = "52"
OP_MSTORE8 = "53"
OP_SLOAD = "54"
OP_SSTORE = "55"
OP_JUMP = "56"
OP_JUMPI = "57"
OP_PC = "58"
OP_MSIZE = "59"
OP_GAS = "5a"
OP_JUMPDEST = "5b"

OP_PUSH1 = "60"
OP_PUSH2 = "61"
OP_PUSH32 = "7f"

OP_DUP1 = "80"
OP_DUP2 = "81"
OP_DUP3 = "82"

OP_SWAP1 = "90"
OP_SWAP2 = "91"

OP_RETURN = "f3"
OP_REVERT = "fd"


def build_nullary_op(opcode: str, iterations: int) -> str:
    """
    Template for opcodes that take 0 inputs and push 1 output (e.g. PC, GAS, ADDRESS).
    We initialize an accumulator (0x00) and then loop: <OP> ADD.
    This creates a data dependency chain.
    """
    setup = OP_PUSH1 + "00"  # Initial accumulator
    loop_body = opcode + OP_ADD
    end = OP_PUSH1 + "00" + OP_MSTORE + OP_PUSH1 + "20" + OP_PUSH1 + "00" + OP_RETURN
    return setup + (loop_body * iterations) + end


def build_unary_op(opcode: str, iterations: int) -> str:
    """
    Template for opcodes that take 1 input and push 1 output (e.g. NOT, ISZERO).
    We initialize an accumulator (0x01) and then loop: <OP>.
    Since it takes 1 and leaves 1, the result just keeps feeding back into the opcode.
    """
    setup = OP_PUSH1 + "01"  # Initial accumulator
    loop_body = opcode
    end = OP_PUSH1 + "00" + OP_MSTORE + OP_PUSH1 + "20" + OP_PUSH1 + "00" + OP_RETURN
    return setup + (loop_body * iterations) + end


def build_binary_op(opcode: str, iterations: int) -> str:
    """
    Template for opcodes that take 2 inputs and push 1 output (e.g. ADD, MUL, SHL).
    Setup: PUSH1 0x01 (Constant), PUSH1 0x01 (Accumulator).
    Loop: DUP2 <OP>. This duplicates the constant, then applies <OP> on (constant, accumulator).
    The result becomes the new accumulator.
    """
    setup = OP_PUSH1 + "01" + OP_PUSH1 + "01"
    loop_body = OP_DUP2 + opcode
    end = OP_PUSH1 + "00" + OP_MSTORE + OP_PUSH1 + "20" + OP_PUSH1 + "00" + OP_RETURN
    return setup + (loop_body * iterations) + end


def build_ternary_op(opcode: str, iterations: int) -> str:
    """
    Template for opcodes that take 3 inputs and push 1 output (e.g. ADDMOD, MULMOD).
    Setup: PUSH1 0x07 (Modulus), PUSH1 0x01 (Operand), PUSH1 0x01 (Accumulator).
    Loop: DUP3 DUP3 <OP>. Duplicates the modulus and operand, applying <OP> on
    (modulus, operand, accumulator). The result becomes the new accumulator.
    """
    setup = OP_PUSH1 + "07" + OP_PUSH1 + "01" + OP_PUSH1 + "01"
    loop_body = OP_DUP3 + OP_DUP3 + opcode
    end = OP_PUSH1 + "00" + OP_MSTORE + OP_PUSH1 + "20" + OP_PUSH1 + "00" + OP_RETURN
    return setup + (loop_body * iterations) + end


def build_memory_op_mload(iterations: int) -> str:
    """
    Template for MLOAD.
    We need pointer chasing to defeat DCE.
    Setup: Store 0x00 at memory address 0x00. Push 0x00 (pointer).
    Loop: MLOAD (reads 0x00 from addr 0x00, which is the new pointer).
    """
    # memory[0x00] = 0x00; stack.push(0x00)
    setup = OP_PUSH1 + "00" + OP_PUSH1 + "00" + OP_MSTORE + OP_PUSH1 + "00"
    loop_body = OP_MLOAD
    end = OP_PUSH1 + "00" + OP_MSTORE + OP_PUSH1 + "20" + OP_PUSH1 + "00" + OP_RETURN
    return setup + (loop_body * iterations) + end


def build_memory_op_mstore(iterations: int) -> str:
    """
    Template for MSTORE.
    Setup: PUSH1 0x00 (Address), PUSH1 0x01 (Value).
    Loop: DUP2 DUP2 MSTORE (duplicate addr and value, then store).
    Note: MSTORE doesn't produce an output on stack, so we just keep DUPing.
    Actually, DUP2 DUP2 MSTORE consumes 2 items and pushes 0, so DUP2 DUP2 perfectly offsets it.
    To create a data dependency, we can increment the value: DUP2 DUP2 MSTORE PUSH1 0x01 ADD.
    """
    setup = OP_PUSH1 + "00" + OP_PUSH1 + "00"  # Addr, Value
    loop_body = OP_DUP2 + OP_DUP2 + OP_MSTORE + OP_PUSH1 + "01" + OP_ADD
    end = OP_PUSH1 + "00" + OP_MSTORE + OP_PUSH1 + "20" + OP_PUSH1 + "00" + OP_RETURN
    return setup + (loop_body * iterations) + end


def generate_state_test(name: str, bytecode: str) -> Dict[str, Any]:
    """Wraps a bytecode payload in a standard Ethereum State Test JSON format."""
    address = "0x00000000000000000000000000000000000000aa"
    
    return {
        name: {
            "env": {
                "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
                "currentDifficulty": "0x020000",
                "currentGasLimit": "0x7fffffffffffffff",
                "currentNumber": "0x01",
                "currentTimestamp": "0x03e8",
                "currentBaseFee": "0x0a"
            },
            "pre": {
                address: {
                    "balance": "0x00",
                    "code": "0x" + bytecode,
                    "nonce": "0x00",
                    "storage": {}
                },
                "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {
                    "balance": "0x0de0b6b3a7640000",
                    "code": "0x",
                    "nonce": "0x00",
                    "storage": {}
                }
            },
            "transaction": {
                "data": ["0x"],
                "gasLimit": ["0x7fffffffffffffff"],
                "gasPrice": "0x0a",
                "nonce": "0x00",
                "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
                "to": address,
                "value": ["0x00"]
            },
            "post": {
                "Cancun": [
                    {
                        "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "indexes": {"data": 0, "gas": 0, "value": 0},
                        "logs": "0x0000000000000000000000000000000000000000000000000000000000000000"
                    }
                ]
            }
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Generate EVM opcode microbenchmarks")
    parser.add_argument("--outdir", required=True, help="Output directory for generated JSON files")
    parser.add_argument("--iterations", type=int, default=10000, help="Number of loop iterations per opcode (default 10000)")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    # Opcode mappings
    benchmarks = {
        # Nullary ops
        "PC": build_nullary_op(OP_PC, args.iterations),
        "GAS": build_nullary_op(OP_GAS, args.iterations),
        "ADDRESS": build_nullary_op(OP_ADDRESS, args.iterations),
        "CALLER": build_nullary_op(OP_CALLER, args.iterations),
        "ORIGIN": build_nullary_op(OP_ORIGIN, args.iterations),
        "CODESIZE": build_nullary_op(OP_CODESIZE, args.iterations),
        "CALLDATASIZE": build_nullary_op(OP_CALLDATASIZE, args.iterations),
        "RETURNDATASIZE": build_nullary_op(OP_RETURNDATASIZE, args.iterations),
        "COINBASE": build_nullary_op(OP_COINBASE, args.iterations),
        "TIMESTAMP": build_nullary_op(OP_TIMESTAMP, args.iterations),
        "NUMBER": build_nullary_op(OP_NUMBER, args.iterations),
        "DIFFICULTY": build_nullary_op(OP_DIFFICULTY, args.iterations),
        "GASLIMIT": build_nullary_op(OP_GASLIMIT, args.iterations),
        "CHAINID": build_nullary_op(OP_CHAINID, args.iterations),
        "BASEFEE": build_nullary_op(OP_BASEFEE, args.iterations),

        # Unary ops
        "ISZERO": build_unary_op(OP_ISZERO, args.iterations),
        "NOT": build_unary_op(OP_NOT, args.iterations),

        # Binary ops
        "ADD": build_binary_op(OP_ADD, args.iterations),
        "MUL": build_binary_op(OP_MUL, args.iterations),
        "SUB": build_binary_op(OP_SUB, args.iterations),
        "DIV": build_binary_op(OP_DIV, args.iterations),
        "SDIV": build_binary_op(OP_SDIV, args.iterations),
        "MOD": build_binary_op(OP_MOD, args.iterations),
        "SMOD": build_binary_op(OP_SMOD, args.iterations),
        "EXP": build_binary_op(OP_EXP, args.iterations),
        "SIGNEXTEND": build_binary_op(OP_SIGNEXTEND, args.iterations),
        "LT": build_binary_op(OP_LT, args.iterations),
        "GT": build_binary_op(OP_GT, args.iterations),
        "SLT": build_binary_op(OP_SLT, args.iterations),
        "SGT": build_binary_op(OP_SGT, args.iterations),
        "EQ": build_binary_op(OP_EQ, args.iterations),
        "AND": build_binary_op(OP_AND, args.iterations),
        "OR": build_binary_op(OP_OR, args.iterations),
        "XOR": build_binary_op(OP_XOR, args.iterations),
        "BYTE": build_binary_op(OP_BYTE, args.iterations),
        "SHL": build_binary_op(OP_SHL, args.iterations),
        "SHR": build_binary_op(OP_SHR, args.iterations),
        "SAR": build_binary_op(OP_SAR, args.iterations),

        # Ternary ops
        "ADDMOD": build_ternary_op(OP_ADDMOD, args.iterations),
        "MULMOD": build_ternary_op(OP_MULMOD, args.iterations),

        # Memory ops
        "MLOAD": build_memory_op_mload(args.iterations),
        "MSTORE": build_memory_op_mstore(args.iterations),
    }

    count = 0
    for name, bytecode in benchmarks.items():
        test_case = generate_state_test(f"opcode_{name}", bytecode)
        outpath = os.path.join(args.outdir, f"opcode_{name}.json")
        with open(outpath, "w") as f:
            json.dump(test_case, f, indent=4)
        count += 1
    
    print(f"Successfully generated {count} opcode benchmark test cases in '{args.outdir}'.")

if __name__ == "__main__":
    main()
