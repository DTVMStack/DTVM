# Copyright (C) 2025 the DTVM authors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import argparse

def evm_to_bytecode(input_file_path, output_file_path):
    """
    parse EVM Assembly instructions and convert them to corresponding bytecode, write to output file.

    Parameters:
        input_file_path (str): input file path, containing text format EVM instructions.
        output_file_path (str): output file path, storing binary bytecode format.
    """

    # EVM OPcode Mnemonic -> Bytecode (Hex), see https://www.evm.codes/
    opcode_map = {
        # 0x: arithmetic operations
        "STOP": "00",
        "ADD": "01",
        "MUL": "02",
        "SUB": "03",
        "DIV": "04",
        "SDIV": "05",
        "MOD": "06",
        "SMOD": "07",
        "ADDMOD": "08",
        "MULMOD": "09",
        "EXP": "0A",
        "SIGNEXTEND": "0B",

        # 1x: comparison and bitwise logic operations
        "LT": "10",
        "GT": "11",
        "SLT": "12",
        "SGT": "13",
        "EQ": "14",
        "ISZERO": "15",
        "AND": "16",
        "OR": "17",
        "XOR": "18",
        "NOT": "19",
        "BYTE": "1A",
        "SHL": "1B",
        "SHR": "1C",
        "SAR": "1D",

        # 2x: cryptographic operations
        "SHA3": "20",

        # 3x: environmental information
        "ADDRESS": "30",
        "BALANCE": "31",
        "ORIGIN": "32",
        "CALLER": "33",
        "CALLVALUE": "34",
        "CALLDATALOAD": "35",
        "CALLDATASIZE": "36",
        "CALLDATACOPY": "37",
        "CODESIZE": "38",
        "CODECOPY": "39",
        "GASPRICE": "3A",
        "EXTCODESIZE": "3B",
        "EXTCODECOPY": "3C",
        "RETURNDATASIZE": "3D",
        "RETURNDATACOPY": "3E",
        "EXTCODEHASH": "3F",

        # 4x: block information
        "BLOCKHASH": "40",
        "COINBASE": "41",
        "TIMESTAMP": "42",
        "NUMBER": "43",
        "DIFFICULTY": "44",
        "GASLIMIT": "45",
        "CHAINID": "46",
        "SELFBALANCE": "47",

        # 5x: storage and memory operations
        "POP": "50",
        "MLOAD": "51",
        "MSTORE": "52",
        "MSTORE8": "53",
        "SLOAD": "54",
        "SSTORE": "55",
        "JUMP": "56",
        "JUMPI": "57",
        "PC": "58",
        "MSIZE": "59",
        "GAS": "5A",
        "JUMPDEST": "5B",

        # 6x: Push operations
        "PUSH1": "60",
        "PUSH2": "61",
        "PUSH3": "62",
        "PUSH4": "63",
        "PUSH5": "64",
        "PUSH6": "65",
        "PUSH7": "66",
        "PUSH8": "67",
        "PUSH9": "68",
        "PUSH10": "69",
        "PUSH11": "6A",
        "PUSH12": "6B",
        "PUSH13": "6C",
        "PUSH14": "6D",
        "PUSH15": "6E",
        "PUSH16": "6F",
        "PUSH17": "70",
        "PUSH18": "71",
        "PUSH19": "72",
        "PUSH20": "73",
        "PUSH21": "74",
        "PUSH22": "75",
        "PUSH23": "76",
        "PUSH24": "77",
        "PUSH25": "78",
        "PUSH26": "79",
        "PUSH27": "7A",
        "PUSH28": "7B",
        "PUSH29": "7C",
        "PUSH30": "7D",
        "PUSH31": "7E",
        "PUSH32": "7F",

        # 8x: Duplicate operations
        "DUP1": "80",
        "DUP2": "81",
        "DUP3": "82",
        "DUP4": "83",
        "DUP5": "84",
        "DUP6": "85",
        "DUP7": "86",
        "DUP8": "87",
        "DUP9": "88",
        "DUP10": "89",
        "DUP11": "8A",
        "DUP12": "8B",
        "DUP13": "8C",
        "DUP14": "8D",
        "DUP15": "8E",
        "DUP16": "8F",

        # 9x: Swap operations
        "SWAP1": "90",
        "SWAP2": "91",
        "SWAP3": "92",
        "SWAP4": "93",
        "SWAP5": "94",
        "SWAP6": "95",
        "SWAP7": "96",
        "SWAP8": "97",
        "SWAP9": "98",
        "SWAP10": "99",
        "SWAP11": "9A",
        "SWAP12": "9B",
        "SWAP13": "9C",
        "SWAP14": "9D",
        "SWAP15": "9E",
        "SWAP16": "9F",

        # Ax: logging operations
        "LOG0": "A0",
        "LOG1": "A1",
        "LOG2": "A2",
        "LOG3": "A3",
        "LOG4": "A4",

        # Fx: system operations
        "CREATE": "F0",
        "CALL": "F1",
        "CALLCODE": "F2",
        "RETURN": "F3",
        "DELEGATECALL": "F4",
        "CREATE2": "F5",
        "STATICCALL": "FA",
        "REVERT": "FD",
        "INVALID": "FE",
        "SELFDESTRUCT": "FF"
    }

    try:
        with open(input_file_path, 'r') as input_file:
            lines = input_file.readlines()

        bytecode = []

        # parse each line of instructions and convert to bytecode
        for line in lines:
            # ignore empty line and comment
            line = line.strip()
            if not line or line.startswith("//"):
                continue

            parts = line.split()
            if len(parts) == 0:
                continue

            mnemonic = parts[0]

            if mnemonic not in opcode_map:
                raise ValueError(f"unknow opcode: {mnemonic}")

            # convert mnemonic to bytecode
            bytecode.append(opcode_map[mnemonic])

            # extract argument part
            if len(parts) > 1:
                argument = parts[1]
                if argument.startswith("0x"):
                    bytecode.append(argument[2:])
                else:
                    bytecode.append(argument)

        # write bytecode to output file
        with open(output_file_path, 'w') as output_file:
            output_file.write("".join(bytecode))
            print(f"bytecode writen to {output_file_path}")

    except FileNotFoundError:
        print(f"error: not found file {input_file_path}")
    except ValueError as ve:
        print(f"error: {ve}")
    except Exception as e:
        print(f"unknow error: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EVM Assembly to Bytecode Converter")
    parser.add_argument("input_file", help="input file path (EVM assembly)")
    parser.add_argument("output_file", help="output file path (bytecode)")

    args = parser.parse_args()
    evm_to_bytecode(args.input_file, args.output_file)
